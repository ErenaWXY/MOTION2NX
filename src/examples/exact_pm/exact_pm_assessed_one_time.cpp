// MIT License
// (c) 2025 — assessment wrapper for Exact Pattern Matching, multi-instance in a single run.
//
// How to run:
//   # Party 0
//   ./build_debwithrelinfo_gcc/bin/exact_pm_assessed \
//     --my-id 0 \
//     --party 0,127.0.0.1,7002 --party 1,127.0.0.1,7003 \
//     --pattern-size 10 --text-size 256 --ring-size 16 \
//     --num-patterns 1024 --sync-between-setup-and-online
//
//   # Party 1
//   ./build_debwithrelinfo_gcc/bin/exact_pm_assessed \
//     --my-id 1 \
//     --party 0,127.0.0.1,7002 --party 1,127.0.0.1,7003 \
//     --pattern-size 10 --text-size 256 --ring-size 16 \
//     --num-patterns 1024 --sync-between-setup-and-online

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

// ------------------------ CLI Options ------------------------
struct Options {
  std::size_t my_id{};
  MOTION::Communication::tcp_parties_config tcp_config;
  std::size_t threads{0};
  bool json{false};
  std::size_t repetitions{1}; // number of batches (each batch builds many instances then run() once)
  bool sync_between_setup_and_online{false};
  std::uint64_t pattern_size{10};
  std::uint64_t text_size{256};
  std::uint64_t ring_size{16};

  // generator (benchmark)
  bool alpha_patterns{true};
  std::size_t num_patterns{1024}; // instances per batch

  // seeds
  uint64_t patt_seed{123456};
  uint64_t text_seed{654321};
};

// ------------------------ RSS helper ------------------------
static long get_rss_kb() {
  { // /proc/self/status → VmRSS
    std::ifstream f("/proc/self/status");
    if (f) {
      std::string line;
      while (std::getline(f, line)) {
        if (line.rfind("VmRSS:", 0) == 0) {
          std::istringstream iss(line);
          std::string key, unit; long value = -1;
          iss >> key >> value >> unit;
          if (value >= 0) return value; // kB
        }
      }
    }
  }
  { // /proc/self/statm (resident pages * pagesize)
    std::ifstream f("/proc/self/statm");
    if (f) {
      long size_pages=-1, rss_pages=-1;
      if (f >> size_pages >> rss_pages) {
        long page_kb = sysconf(_SC_PAGESIZE) / 1024;
        if (rss_pages >= 0 && page_kb > 0) return rss_pages * page_kb;
      }
    }
  }
  { // getrusage (max RSS; Linux: kB)
    struct rusage ru{};
    if (getrusage(RUSAGE_SELF, &ru) == 0 && ru.ru_maxrss > 0) return ru.ru_maxrss;
  }
  return -1;
}

// ------------------------ Communication counters ------------------------
struct CommDelta {
  uint64_t bytes_sent{0};
  uint64_t bytes_recv{0};
  uint64_t msgs_sent{0};
  uint64_t msgs_recv{0};
};

static CommDelta get_comm_delta_and_reset(MOTION::Communication::CommunicationLayer& cl) {
  const auto stats_vec = cl.get_transport_statistics();
  CommDelta c{};
  for (const auto& s : stats_vec) {
    c.bytes_sent += static_cast<uint64_t>(s.num_bytes_sent);
    c.bytes_recv += static_cast<uint64_t>(s.num_bytes_received);
    c.msgs_sent  += static_cast<uint64_t>(s.num_messages_sent);
    c.msgs_recv  += static_cast<uint64_t>(s.num_messages_received);
  }
  cl.reset_transport_statistics();
  return c;
}

static uint64_t rounds_from(const CommDelta& c) {
  // Rounds ≈ max(messages sent, messages received)
  return std::max(c.msgs_sent, c.msgs_recv);
}

// ------------------------ Benchmark data generation ------------------------
static std::string rand_alpha_str(std::size_t len, std::mt19937& rng) {
  static constexpr char alphabet[] = "abcdefghijklmnopqrstuvwxyz";
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

static std::vector<MOTION::NewWireP> cast_wires(BooleanBEAVYWireVector& wires) {
  return std::vector<MOTION::NewWireP>(std::begin(wires), std::end(wires));
}

// ------------------------ Build Boolean inputs from generated data ------------------------
// This encodes text/pattern into M*R Boolean BEAVY wires with num_simd lanes.
// Notes:
// - M = pattern_size, T = text_size, R = ring_size, num_simd = T - M + 1, num_wires = M*R
// - For each wire j (corresponding to position pos=j/R in the pattern), lane s stores
//   eq = (text[s + pos] == patt[pos]).
// - We replicate the same per-pos eq across R wires (to fill M*R wires as expected by the core).
// - XOR secret sharing: pick public dx randomly, set secret mx = dx XOR eq.
// - Goal: feed generated data into the circuit for benchmarking. We do NOT open outputs.
static WireVector make_boolean_inputs_for_pm_from_data(const Options& opt,
                                                       const std::string& text,
                                                       const std::string& patt) {
  const auto M = opt.pattern_size;
  const auto T = opt.text_size;
  const auto R = opt.ring_size;

  if (patt.size() != M || text.size() != T) {
    throw std::runtime_error("Text/pattern size mismatch with CLI parameters");
    }

  const auto num_simd  = T - M + 1;
  const auto num_wires = M * R;

  BooleanBEAVYWireVector wires;
  wires.reserve(num_wires);

  std::mt19937 rng(0xC0FFEE); // local PRNG only for dx

  for (std::size_t j = 0; j < num_wires; ++j) {
    const std::size_t pos = j / R; // character index in pattern (0..M-1)

    auto w = std::make_shared<BooleanBEAVYWire>(num_simd);
    ENCRYPTO::BitVector<> mx(num_simd); // secret share
    ENCRYPTO::BitVector<> dx(num_simd); // public share

    for (std::size_t s = 0; s < num_simd; ++s) {
      const bool eq = (text[s + pos] == patt[pos]);
      const bool dx_bit = static_cast<bool>(rng() & 1);
      const bool mx_bit = dx_bit ^ eq;
      dx.Set(s, dx_bit);
      mx.Set(s, mx_bit);
    }

    w->get_secret_share() = std::move(mx);
    w->get_public_share() = std::move(dx);
    w->set_setup_ready();
    w->set_online_ready();
    wires.push_back(std::move(w));
  }

  return cast_wires(wires);
}

// ------------------------ Random Boolean inputs (fallback) ------------------------
static WireVector make_boolean_inputs_for_pm_random(const Options& opt) {
  const auto num_simd = opt.text_size - opt.pattern_size + 1;
  const auto num_wires = opt.pattern_size * opt.ring_size;
  BooleanBEAVYWireVector wires;
  wires.reserve(num_wires);
  for (uint64_t j = 0; j < num_wires; ++j) {
    auto w = std::make_shared<BooleanBEAVYWire>(num_simd);
    ENCRYPTO::BitVector<> mx = ENCRYPTO::BitVector<>::Random(num_simd);
    ENCRYPTO::BitVector<> dx = ENCRYPTO::BitVector<>::Random(num_simd);
    w->get_secret_share() = std::move(mx);
    w->get_public_share() = std::move(dx);
    w->set_setup_ready();
    w->set_online_ready();
    wires.push_back(std::move(w));
  }
  return cast_wires(wires);
}

// ------------------------ RHS parameter for EQEXP ------------------------
// The core uses the first public element as vec_size. Keep it = 2*(M*R) as before.
static std::vector<MOTION::NewWireP> make_eqexp_rhs_wire(const Options& opt) {
  const auto num_simd = opt.text_size - opt.pattern_size + 1;
  const auto num_wires = opt.pattern_size * opt.ring_size;
  auto wire = std::make_shared<ArithmeticBEAVYWire<uint64_t>>(num_simd);
  std::vector<uint64_t> x(num_simd, 2 * num_wires); // vec_size = 2*(M*R)
  wire->get_secret_share() = x;
  wire->get_public_share() = x;
  wire->set_setup_ready();
  wire->set_online_ready();
  std::vector<NewWireP> v; v.push_back(wire);
  return v;
}

// ------------------------ Communication layer setup ------------------------
static std::unique_ptr<MOTION::Communication::CommunicationLayer>
setup_communication(const Options& opt) {
  MOTION::Communication::TCPSetupHelper helper(opt.my_id, opt.tcp_config);
  return std::make_unique<MOTION::Communication::CommunicationLayer>(
      opt.my_id, helper.setup_connections());
}

// ------------------------ Phase printer ------------------------
static void print_phase(const char* name,
                        std::chrono::steady_clock::duration dur,
                        const CommDelta& c,
                        long rss_kb) {
  using namespace std::chrono;
  std::cout << "[PHASE] " << name
            << " | ms=" << std::chrono::duration_cast<std::chrono::milliseconds>(dur).count()
            << " | bytes_sent=" << c.bytes_sent
            << " | bytes_recv=" << c.bytes_recv
            << " | msgs_sent="  << c.msgs_sent
            << " | msgs_recv="  << c.msgs_recv
            << " | rounds≈"     << rounds_from(c)
            << " | rss_kb="     << rss_kb
            << std::endl;
}

// ------------------------ Extract ms from MOTION stats text ------------------------
static double extract_ms(const std::string& txt, const char* label) {
  std::regex re(std::string("^") + label + R"(\s+([0-9.]+)\s+ms)",
                std::regex::icase | std::regex::multiline);
  std::smatch m;
  if (std::regex_search(txt, m, re)) return std::stod(m[1]);
  return -1.0;
}

// ------------------------ Observer to split preprocessing/online ------------------------
struct SplitObserver : public MOTION::PhaseObserver {
  MOTION::Communication::CommunicationLayer& cl;
  Clock::time_point t_pre_start{};
  Clock::time_point t_pre_end{};
  CommDelta comm_pre{};
  bool got_pre{false};
  explicit SplitObserver(MOTION::Communication::CommunicationLayer& ref) : cl(ref) {}
  void on_preprocessing_done() override {
    t_pre_end = Clock::now();
    comm_pre = get_comm_delta_and_reset(cl);
    got_pre = true;
  }
};

// ------------------------ CLI parse ------------------------
static std::optional<Options> parse_cli(int argc, char** argv) {
  Options opt;
  po::options_description desc("Exact PM (assessed, multi-instances in one run) options");
  desc.add_options()
    ("help,h", po::bool_switch()->default_value(false), "Show help")
    ("my-id", po::value<std::size_t>()->required(), "My party id (0 or 1)")
    ("party", po::value<std::vector<std::string>>()->multitoken()->required(),
       "(id,host,port) for both parties, e.g. --party 0,127.0.0.1,7002 --party 1,127.0.0.1,7003")
    ("threads", po::value<std::size_t>()->default_value(0), "Worker threads for backend")
    ("json", po::bool_switch()->default_value(false), "Print final stats in JSON")
    ("repetitions", po::value<std::size_t>()->default_value(1), "Number of batches (each batch builds many instances then runs once)")
    ("sync-between-setup-and-online", po::bool_switch()->default_value(false),
       "Insert a sync point between preprocessing and online")
    ("pattern-size", po::value<std::uint64_t>()->default_value(10), "Pattern length")
    ("text-size", po::value<std::uint64_t>()->default_value(256), "Text length")
    ("ring-size", po::value<std::uint64_t>()->default_value(16), "Ring size")
    ("alpha-patterns", po::bool_switch()->default_value(true), "Use a-z generator for benchmark")
    ("num-patterns", po::value<std::size_t>()->default_value(1024), "Instances per batch (built into one run)")
    ("patt-seed", po::value<uint64_t>()->default_value(123456), "Pattern seed")
    ("text-seed", po::value<uint64_t>()->default_value(654321), "Text seed")
  ;
  po::variables_map vm;
  try {
    po::store(po::parse_command_line(argc, argv, desc), vm);
    if (vm["help"].as<bool>()) { std::cout << desc << "\n"; return std::nullopt; }
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
    const static std::regex re("([01]),([^,]+),(\\d{1,5})");
    std::smatch m;
    if (!std::regex_match(s, m, re)) throw std::invalid_argument("invalid --party");
    return {boost::lexical_cast<std::size_t>(m[1]),
            MOTION::Communication::tcp_connection_config{m[2], boost::lexical_cast<uint16_t>(m[3])}};
      };

  opt.tcp_config.resize(2);
  auto [id0, c0] = parse_party_argument(party_infos[0]);
  auto [id1, c1] = parse_party_argument(party_infos[1]);
  if (id0 == id1) { std::cerr << "party ids must differ (0 and 1)\n"; return std::nullopt; }
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

// ------------------------ main ------------------------
int main(int argc, char** argv) {
  std::cerr << "[exact_pm_assessed HAM+EQEXP batch-in-one-run] " __DATE__ " " __TIME__ << std::endl;
  auto opt = parse_cli(argc, argv);
  if (!opt) return 1;

  try {
    // (A) Generate text/pattern (these will be fed into the circuit)
    std::vector<std::string> pats;
    std::string text;
    if (opt->alpha_patterns) {
      pats = make_alpha_patterns(opt->num_patterns, opt->pattern_size, opt->patt_seed);
      text = make_alpha_text(opt->text_size, opt->text_seed);
    }

    // (B) Shared communication layer
    auto comm = setup_communication(*opt);
    auto logger = std::make_shared<MOTION::Logger>(opt->my_id,
                                                   boost::log::trivial::severity_level::trace);
    comm->set_logger(logger);

    // Fixed parameters for logging
    const auto num_simd  = opt->text_size - opt->pattern_size + 1;
    const auto num_wires = opt->pattern_size * opt->ring_size;
    std::cout << "num_simd: "  << num_simd  << "\n";
    std::cout << "num_wires: " << num_wires << "\n";
    std::cout << "vs: " << (2 * num_wires) << "\n";
    std::cout << "instances_per_run: " << opt->num_patterns << "\n";

    for (std::size_t rep = 0; rep < opt->repetitions; ++rep) {
      std::cout << "==== BATCH " << (rep+1) << "/" << opt->repetitions << " ====\n";

      // ===== (i) SECRET SHARING / BUILD GRAPH for the whole batch (local only) =====
      const auto rss0 = get_rss_kb();
      const auto t0 = Clock::now();

      // One backend for the entire batch
      MOTION::TwoPartyBackend backend(*comm, opt->threads,
                                      opt->sync_between_setup_and_online, logger);

      auto& gf_bool  = backend.get_gate_factory(MOTION::MPCProtocol::BooleanBEAVY);
      auto& gf_arith = backend.get_gate_factory(MOTION::MPCProtocol::ArithmeticBEAVY);

      // Build num_patterns instances into a single run: feed generated data
      for (std::size_t inst = 0; inst < opt->num_patterns; ++inst) {
        const auto& patt = opt->alpha_patterns ? pats[inst] : std::string(opt->pattern_size, 'a');
        const auto& txt  = opt->alpha_patterns ? text       : std::string(opt->text_size, 'a');

        // Build inputs from generated data (XOR shares)
        const auto in_bool = make_boolean_inputs_for_pm_from_data(*opt, txt, patt);
        const auto in_rhs  = make_eqexp_rhs_wire(*opt);

        // Circuit: HAM (Boolean BEAVY) -> EQEXP (Arithmetic BEAVY)
        auto ham = gf_bool.make_unary_gate(ENCRYPTO::PrimitiveOperationType::HAM, in_bool);
        (void)gf_arith.make_binary_gate(ENCRYPTO::PrimitiveOperationType::EQEXP, ham, in_rhs);
      }

      const auto t1 = Clock::now();
      const auto build_inputs_and_graph = t1 - t0;

      // ===== (ii) PREPROCESSING + (iii) ONLINE =====
      auto hook = std::make_shared<SplitObserver>(*comm);
      hook->t_pre_start = Clock::now();
      comm->reset_transport_statistics();
      backend.set_phase_observer(hook);

      const auto t_run_start = Clock::now();
      backend.run();
      const auto t_run_end   = Clock::now();

      // Online comm after observer split
      const auto comm_online = get_comm_delta_and_reset(*comm);

      // Print three phases
      print_phase("secret_share+build", build_inputs_and_graph, {/*no comm*/0,0,0,0}, rss0);
      if (!hook->got_pre) {
        std::cerr << "[WARN] PhaseObserver did not fire; cannot split preprocessing/online precisely.\n";
      }
      const auto pre_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                            hook->t_pre_end - hook->t_pre_start);
      print_phase("preprocessing", pre_ms, hook->comm_pre, get_rss_kb());

      const auto online_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                               t_run_end - hook->t_pre_end);
      print_phase("online", online_ms, comm_online, get_rss_kb());

      // MOTION stats (aggregated inside backend)
      {
        MOTION::Statistics::AccumulatedRunTimeStats run_time_stats;
        MOTION::Statistics::AccumulatedCommunicationStats comm_stats;
        run_time_stats.add(backend.get_run_time_stats());
        const auto stats_txt = MOTION::Statistics::print_stats("Exact Pattern Matching",
                                                               run_time_stats, comm_stats);
        const double ms_prep_total   = extract_ms(stats_txt, "Preprocessing Total");
        const double ms_gates_setup  = extract_ms(stats_txt, "Gates Setup");
        const double ms_gates_online = extract_ms(stats_txt, "Gates Online");
        std::cout << "[MOTION] preprocessing_ms=" << ms_prep_total
                  << " | gates_setup_ms=" << ms_gates_setup
                  << " | gates_online_ms=" << ms_gates_online << std::endl;
      }

      // Clean up between batches
      comm->sync();
      comm->reset_transport_statistics();
    }

    comm->shutdown();
  } catch (const std::exception& e) {
    std::cerr << "ERROR: " << e.what() << "\n";
    return 2;
  }
  return 0;
}
