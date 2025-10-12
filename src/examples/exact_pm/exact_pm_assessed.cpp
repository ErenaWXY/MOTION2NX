// MIT License
// (c) 2025 — assessment wrapper for Exact Pattern Matching, non-intrusive to existing example.

#include <algorithm>
#include <chrono>
#include <fstream>
#include <iostream>
#include <optional>
#include <random>
#include <regex>
#include <stdexcept>
#include <string>
#include <vector>

#include <boost/lexical_cast.hpp>
#include <boost/program_options.hpp>

#include "base/two_party_backend.h"
#include "communication/communication_layer.h"
#include "communication/tcp_transport.h"
#include "protocols/beavy/beavy_provider.h"
#include "protocols/beavy/gate.h"
#include "protocols/beavy/wire.h"
#include "statistics/analysis.h"
#include "utility/bit_vector.h"
#include "utility/helpers.h"
#include "utility/logger.h"
#include "wire/new_wire.h"

#include <sys/resource.h>
#include <unistd.h>
#include <sstream>

namespace po = boost::program_options;
using Clock = std::chrono::steady_clock;
using NewWire = MOTION::NewWire;
using NewWireP = std::shared_ptr<NewWire>;
using WireVector = std::vector<NewWireP>;
using namespace MOTION::proto::beavy;

struct Options {
  std::size_t my_id{};
  MOTION::Communication::tcp_parties_config tcp_config;
  std::size_t threads{0};
  bool json{false};
  std::size_t repetitions{1};
  bool sync_between_setup_and_online{false};
  std::uint64_t pattern_size{10};
  std::uint64_t text_size{256};
  std::uint64_t ring_size{16};
  // generator
  bool alpha_patterns{true};
  std::size_t num_patterns{1024}; // number of patterns (each length = pattern_size)
  // seed
  uint64_t patt_seed{123456};
  uint64_t text_seed{654321};
};

static long get_rss_kb() {
  // Prefer read /proc/self/status (VmRSS: <num> kB)
  {
    std::ifstream f("/proc/self/status");
    if (f) {
      std::string line;
      while (std::getline(f, line)) {
        if (line.rfind("VmRSS:", 0) == 0) {
          std::istringstream iss(line);
          std::string key, unit;
          long value = -1;
          iss >> key >> value >> unit; // key="VmRSS:", unit="kB"
          if (value >= 0) return value; // kB
        }
      }
    }
  }

  // Fallback 1: /proc/self/statm (resident pages * pagesize)
  {
    std::ifstream f("/proc/self/statm");
    if (f) {
      long size_pages=-1, rss_pages=-1;
      if (f >> size_pages >> rss_pages) {
        long page_kb = sysconf(_SC_PAGESIZE) / 1024;
        if (rss_pages >= 0 && page_kb > 0) return rss_pages * page_kb;
      }
    }
  }

  // Fallback 2: getrusage (max RSS; on Linux is kB)
  {
    struct rusage ru{};
    if (getrusage(RUSAGE_SELF, &ru) == 0 && ru.ru_maxrss > 0) {
      return ru.ru_maxrss; // kB
    }
  }
  return -1;
}

struct CommDelta {
  uint64_t bytes_sent;
  uint64_t bytes_recv;
  uint64_t msgs_sent;
  uint64_t msgs_recv;
};

static uint64_t estimate_rounds_from_msgs(const CommDelta& c) {
  return std::max(c.msgs_sent, c.msgs_recv);
}

static CommDelta get_comm_delta_and_reset(MOTION::Communication::CommunicationLayer& cl) {
  const auto stats_vec = cl.get_transport_statistics();  // vector<TransportStatistics>

  uint64_t bytes_sent = 0, bytes_recv = 0, msgs_sent = 0, msgs_recv = 0;
  for (const auto& s : stats_vec) {
    bytes_sent += static_cast<uint64_t>(s.num_bytes_sent);
    bytes_recv += static_cast<uint64_t>(s.num_bytes_received);
    msgs_sent  += static_cast<uint64_t>(s.num_messages_sent);
    msgs_recv  += static_cast<uint64_t>(s.num_messages_received);
  }

  cl.reset_transport_statistics();
  return {bytes_sent, bytes_recv, msgs_sent, msgs_recv};
}

static std::string rand_alpha_str(std::size_t len, std::mt19937& rng) {
  static constexpr char alphabet[] =
      "abcdefghijklmnopqrstuvwxyz";
  std::uniform_int_distribution<std::size_t> dist(0, sizeof(alphabet) - 2);
  std::string s; s.resize(len);
  for (std::size_t i = 0; i < len; ++i) s[i] = alphabet[dist(rng)];
  return s;
}

static std::vector<std::string> make_alpha_patterns(std::size_t n, std::size_t len, uint64_t seed) {
  std::mt19937 rng(static_cast<uint32_t>(seed));
  std::vector<std::string> out; out.reserve(n);
  for (std::size_t i = 0; i < n; ++i) out.push_back(rand_alpha_str(len, rng));
  return out;
}

static std::string make_alpha_text(std::size_t len, uint64_t seed) {
  std::mt19937 rng(static_cast<uint32_t>(seed));
  return rand_alpha_str(len, rng);
}

static std::vector<std::shared_ptr<NewWire>> cast_wires(BooleanBEAVYWireVector& wires) {
  return std::vector<std::shared_ptr<NewWire>>(std::begin(wires), std::end(wires));
}

// Secret-share-ish input preparation for the Boolean BEAVY HAM gate
static WireVector make_boolean_inputs_for_pm(const Options& opt) {
  const auto num_simd = opt.text_size - opt.pattern_size + 1;
  const auto num_wires = opt.pattern_size * opt.ring_size;
  std::cout << "num_simd: " << num_simd << "\n";
  std::cout << "num_wires: " << num_wires << "\n";
  BooleanBEAVYWireVector wires;
  wires.reserve(num_wires);
  for (uint64_t j = 0; j < num_wires; ++j) {
    auto w = std::make_shared<BooleanBEAVYWire>(num_simd);
    ENCRYPTO::BitVector<> mx = ENCRYPTO::BitVector<>::Random(num_simd);
    ENCRYPTO::BitVector<> dx = ENCRYPTO::BitVector<>::Random(num_simd);
    w->get_secret_share() = mx;
    w->get_public_share() = dx;
    w->set_setup_ready();
    w->set_online_ready();
    wires.push_back(std::move(w));
  }
  return cast_wires(wires);
}

// Arithmetic BEAVY wire used in EQEXP
static std::vector<MOTION::NewWireP> make_eqexp_rhs_wire(const Options& opt) {
  const auto num_simd = opt.text_size - opt.pattern_size + 1; // number of the windows
  const auto num_wires = opt.pattern_size * opt.ring_size; // 10 * 8 => 80
  auto wire = std::make_shared<ArithmeticBEAVYWire<uint64_t>>(num_simd);
  std::vector<uint64_t> x(num_simd, 2 * num_wires);
  wire->get_secret_share() = x;
  wire->get_public_share() = x;
  wire->set_setup_ready();
  wire->set_online_ready();
  std::vector<NewWireP> v; v.push_back(wire);
  return v;
}

static std::unique_ptr<MOTION::Communication::CommunicationLayer>
setup_communication(const Options& opt) {
  MOTION::Communication::TCPSetupHelper helper(opt.my_id, opt.tcp_config);
  return std::make_unique<MOTION::Communication::CommunicationLayer>(opt.my_id,
                                                                     helper.setup_connections());
}

static void print_phase(const char* name,
                        std::chrono::steady_clock::duration dur,
                        const CommDelta& c,
                        long rss_kb) {
  using namespace std::chrono;
  std::cout << "[PHASE] " << name
            << " | ms=" << duration_cast<milliseconds>(dur).count()
            << " | bytes_sent=" << c.bytes_sent
            << " | bytes_recv=" << c.bytes_recv
            << " | msgs_sent="  << c.msgs_sent
            << " | msgs_recv="  << c.msgs_recv
            << " | rss_kb="     << rss_kb
            << std::endl;
}

static std::optional<Options> parse_cli(int argc, char** argv) {
  Options opt;
  po::options_description desc("Exact PM (assessed) options");
  desc.add_options()
    ("help,h", po::bool_switch()->default_value(false), "Show help")
    ("my-id", po::value<std::size_t>()->required(), "My party id (0 or 1)")
    ("party", po::value<std::vector<std::string>>()->multitoken()->required(),
       "(id,host,port) for both parties, e.g. --party 0,127.0.0.1,7002 --party 1,127.0.0.1,7003")
    ("threads", po::value<std::size_t>()->default_value(0), "Worker threads for backend")
    ("json", po::bool_switch()->default_value(false), "Print final stats in JSON")
    ("repetitions", po::value<std::size_t>()->default_value(1), "Repetitions")
    ("sync-between-setup-and-online", po::bool_switch()->default_value(false),
       "Insert a sync point between preprocessing and online")
    // workload
    ("pattern-size", po::value<std::uint64_t>()->default_value(10), "Pattern length")
    ("text-size", po::value<std::uint64_t>()->default_value(256), "Text length")
    ("ring-size", po::value<std::uint64_t>()->default_value(16), "Ring size")
    // generator
    ("alpha-patterns", po::bool_switch()->default_value(true), "Use a-z generator")
    ("num-patterns", po::value<std::size_t>()->default_value(1024), "Number of patterns")
    ("patt-seed", po::value<uint64_t>()->default_value(123456), "Pattern seed")
    ("text-seed", po::value<uint64_t>()->default_value(654321), "Text seed")
  ;
  po::variables_map vm;
  try {
    po::store(po::parse_command_line(argc, argv, desc), vm);
    if (vm["help"].as<bool>()) {
      std::cout << desc << "\n";
      return std::nullopt;
    }
    po::notify(vm);
  } catch (const std::exception& e) {
    std::cerr << "CLI error: " << e.what() << "\n" << desc << "\n";
    return std::nullopt;
  }

  opt.my_id = vm["my-id"].as<std::size_t>();
  const auto party_infos = vm["party"].as<std::vector<std::string>>();
  if (party_infos.size() != 2) {
    std::cerr << "Provide exactly two --party entries\n";
    return std::nullopt;
  }

  const auto parse_party_argument =
      [](const auto& s) -> std::pair<std::size_t, MOTION::Communication::tcp_connection_config> {
    const static std::regex re("([012]),([^,]+),(\\d{1,5})");
    std::smatch m;
    if (!std::regex_match(s, m, re)) throw std::invalid_argument("invalid --party");
    return {boost::lexical_cast<std::size_t>(m[1]),
            MOTION::Communication::tcp_connection_config{m[2], boost::lexical_cast<uint16_t>(m[3])}};
      };

  opt.tcp_config.resize(2);
  auto [id0, c0] = parse_party_argument(party_infos[0]);
  auto [id1, c1] = parse_party_argument(party_infos[1]);
  if (id0 == id1) {
    std::cerr << "party ids must differ (0 and 1)\n";
    return std::nullopt;
  }
  opt.tcp_config[id0] = c0; opt.tcp_config[id1] = c1;

  opt.threads = vm["threads"].as<std::size_t>();
  opt.json = vm["json"].as<bool>();
  opt.repetitions = vm["repetitions"].as<std::size_t>();
  opt.sync_between_setup_and_online = vm["sync-between-setup-and-online"].as<bool>();
  opt.pattern_size = vm["pattern-size"].as<std::uint64_t>();
  opt.text_size = vm["text-size"].as<std::uint64_t>();
  opt.ring_size = vm["ring-size"].as<std::uint64_t>();
  opt.alpha_patterns = vm["alpha-patterns"].as<bool>();
  opt.num_patterns = vm["num-patterns"].as<std::size_t>();
  opt.patt_seed = vm["patt-seed"].as<uint64_t>();
  opt.text_seed = vm["text-seed"].as<uint64_t>();

  if (opt.pattern_size >= opt.text_size) {
    std::cerr << "pattern-size must be < text-size\n";
    return std::nullopt;
  }
  return opt;
}

static double extract_ms(const std::string& txt, const char* label) {
  std::regex re(std::string("^") + label + R"(\s+([0-9.]+)\s+ms)",
                std::regex::icase | std::regex::multiline);
  std::smatch m;
  if (std::regex_search(txt, m, re)) return std::stod(m[1]);
  return -1.0; 
}

int main(int argc, char** argv) {
  auto opt = parse_cli(argc, argv);
  if (!opt) return 1;

  try {
    // ===== (i) SECRET SHARING / INPUT PREP =====
    auto rss0 = get_rss_kb();
    auto t0 = Clock::now();

    // generator (patterns/text) —
    if (opt->alpha_patterns) {
      auto patt = make_alpha_patterns(opt->num_patterns, opt->pattern_size, opt->patt_seed);
      auto text = make_alpha_text(opt->text_size, opt->text_seed);
      // For log
      if (opt->my_id == 0) {
        std::cout << "[GEN] patterns=" << patt.size()
                  << " len=" << opt->pattern_size
                  << " | text_len=" << text.size() << "\n";
      }
    }

    // Create wires
    auto in_bool = make_boolean_inputs_for_pm(*opt);
    auto in_rhs  = make_eqexp_rhs_wire(*opt);

    auto t1 = Clock::now();
    auto secret_share_dur = t1 - t0;

    // ===== comm layer & logger =====
    auto comm = setup_communication(*opt);
    auto logger = std::make_shared<MOTION::Logger>(opt->my_id,
                                                   boost::log::trivial::severity_level::trace);
    comm->set_logger(logger);

    // Reset counters before jump into pre-processing
    comm->reset_transport_statistics();

    // ===== (ii) PRE-PROCESSING =====
    auto rss1 = get_rss_kb();
    auto t2 = Clock::now();

    MOTION::TwoPartyBackend backend(*comm, opt->threads,
                                    opt->sync_between_setup_and_online, logger);

    // Build circuit exactly same with original (HAM -> EQEXP)
    auto& gf_bool = backend.get_gate_factory(MOTION::MPCProtocol::BooleanBEAVY);
    auto& gf_arith= backend.get_gate_factory(MOTION::MPCProtocol::ArithmeticBEAVY);
    auto ham = gf_bool.make_unary_gate(ENCRYPTO::PrimitiveOperationType::HAM, in_bool);
    auto out = gf_arith.make_binary_gate(ENCRYPTO::PrimitiveOperationType::EQEXP, ham, in_rhs);

    if (opt->sync_between_setup_and_online) comm->sync();

    auto t3 = Clock::now();
    auto comm_pre = get_comm_delta_and_reset(*comm);
    print_phase("secret_share", secret_share_dur, {/*no comm in local prep*/0,0,0,0}, rss0);
    std::cout << "[ROUNDS PHASE] secret_share≈ " << 0 << std::endl;

    print_phase("preprocessing", t3 - t2, comm_pre, rss1);
    std::cout << "[ROUNDS PHASE] preprocessing≈ "
              << estimate_rounds_from_msgs(comm_pre) << std::endl;

    // ===== (iii) ONLINE =====
    auto rss2 = get_rss_kb();
    auto t4 = Clock::now();
    backend.run();  // run evaluate + reveal follow lib
    auto t5 = Clock::now();

    // Collect General statistical (after run)
    auto comm_online = get_comm_delta_and_reset(*comm);
    print_phase("online", t5 - t4, comm_online, rss2);
    std::cout << "[ROUNDS PHASE] online≈ "
              << estimate_rounds_from_msgs(comm_online) << std::endl;

    // ===== Extra: per-window stats & rounds proxy (print only) =====
    {
      const double num_windows = static_cast<double>(opt->text_size - opt->pattern_size + 1);

      const double pre_bytes = static_cast<double>(comm_pre.bytes_sent) + static_cast<double>(comm_pre.bytes_recv);
      const double pre_msgs  = static_cast<double>(comm_pre.msgs_sent)  + static_cast<double>(comm_pre.msgs_recv);
      const double pre_bpw   = (num_windows > 0) ? pre_bytes / num_windows : 0.0;   // bytes per window
      const double pre_mpw   = (num_windows > 0) ? pre_msgs  / num_windows : 0.0;   // msgs per window

      const double on_bytes  = static_cast<double>(comm_online.bytes_sent) + static_cast<double>(comm_online.bytes_recv);
      const double on_msgs   = static_cast<double>(comm_online.msgs_sent)  + static_cast<double>(comm_online.msgs_recv);
      const double on_bpw    = (num_windows > 0) ? on_bytes / num_windows : 0.0;
      const double on_mpw    = (num_windows > 0) ? on_msgs  / num_windows : 0.0;

      const double on_rounds_proxy = (num_windows > 0) ? (on_mpw / 2.0) : 0.0;

      std::cout << "[STATS] preprocessing_total_bytes=" << static_cast<uint64_t>(pre_bytes)
                << " | preprocessing_total_msgs="      << static_cast<uint64_t>(pre_msgs)
                << " | pre_bytes_per_window="          << pre_bpw
                << " | pre_msgs_per_window="           << pre_mpw
                << std::endl;

      std::cout << "[STATS] online_total_bytes="       << static_cast<uint64_t>(on_bytes)
                << " | online_total_msgs="             << static_cast<uint64_t>(on_msgs)
                << " | online_bytes_per_window="       << on_bpw
                << " | online_msgs_per_window="        << on_mpw
                << " | online_rounds_proxy≈"           << on_rounds_proxy
                << std::endl;
    }

    // ===== Parse MOTION stats to get per-phase ms (offline/online) =====
    {
      MOTION::Statistics::AccumulatedRunTimeStats run_time_stats;
      MOTION::Statistics::AccumulatedCommunicationStats comm_stats; 
      run_time_stats.add(backend.get_run_time_stats());

      auto stats_txt = MOTION::Statistics::print_stats("Exact Pattern Matching",
                                                      run_time_stats, comm_stats);

      const double ms_prep_total = extract_ms(stats_txt, "Preprocessing Total");
      const double ms_gates_setup = extract_ms(stats_txt, "Gates Setup");
      const double ms_gates_online = extract_ms(stats_txt, "Gates Online");

      std::cout << "[MOTION] preprocessing_ms=" << ms_prep_total
                << " | gates_setup_ms=" << ms_gates_setup
                << " | gates_online_ms=" << ms_gates_online << std::endl;
    }

    comm->shutdown();

    // Can extend here for the Json print out
  } catch (const std::exception& e) {
    std::cerr << "ERROR: " << e.what() << "\n";
    return 2;
  }
  return 0;
}
