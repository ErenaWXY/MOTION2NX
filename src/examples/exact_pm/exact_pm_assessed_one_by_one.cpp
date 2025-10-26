// MIT License
// (c) 2025 — Assessment wrapper for Exact Pattern Matching, sequential multi-pattern runner.
//
// Usage:
//   # Party 0
//   ./build_debwithrelinfo_gcc/bin/exact_pm_assessed \
//     --my-id 0 \
//     --party 0,127.0.0.1,7002 --party 1,127.0.0.1,7003 \
//     --pattern-size 10 --text-size 256 --ring-size 16 \
//     --num-patterns 1024 --sync-between-setup-and-online [--feed-generated]
//
//   # Party 1
//   ./build_debwithrelinfo_gcc/bin/exact_pm_assessed \
//     --my-id 1 \
//     --party 0,127.0.0.1,7002 --party 1,127.0.0.1,7003 \
//     --pattern-size 10 --text-size 256 --ring-size 16 \
//     --num-patterns 1024 --sync-between-setup-and-online [--feed-generated]
//
// Notes:
// - By default inputs are synthetic shares (random) matching the shape of the circuit.
// - If --feed-generated is set, we deterministically encode generated text/pattern
//   into BooleanBEAVY wires (constant shares). No outputs are revealed.

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

// ------------------------ Options ------------------------
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
  bool alpha_patterns{true};
  std::size_t num_patterns{1024};
  uint64_t patt_seed{123456};
  uint64_t text_seed{654321};
  bool per_run_log{true};
  bool feed_generated{false}; // NEW: feed generated text/pattern into wires
};

// ------------------------ Helpers ------------------------
// How to get the current ram for the phase
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
          if (value >= 0) return value;
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

// Communication rounds use the max msg sent and msg received
static uint64_t rounds_from(const CommDelta& c) {
  return std::max(c.msgs_sent, c.msgs_recv);
}

// Generated patterns and text
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

// Encode helper: map 'a'.. to value in [0, ring_size).
static inline uint32_t sym_val(char c, uint32_t ring_size) {
  uint32_t v = static_cast<uint32_t>((c >= 'a' && c <= 'z') ? (c - 'a') : (c & 0x7F));
  return ring_size ? (v % ring_size) : 0;
}

// Build BooleanBEAVY inputs from generated text/pattern (constant shares; no reveal).
// For each pattern position j and ring bucket r, we set a bit per SIMD lane i if
//   ( text[i + j] maps to r ) and ( pattern[j] maps to r ).
// This is a simple one-hot coincidence encoding; it preserves shape and drives the same
// circuit cost as random inputs.

static WireVector make_boolean_inputs_for_pm_from_data(
    const Options& opt,
    const std::string& text,
    const std::string& pattern) {

  const auto num_simd  = opt.text_size - opt.pattern_size + 1;
  const auto num_wires = opt.pattern_size * opt.ring_size;

  if (text.size() != opt.text_size || pattern.size() != opt.pattern_size) {
    throw std::runtime_error("text/pattern sizes do not match CLI sizes");
  }

  std::cout << "num_simd: " << num_simd << "\n";
  std::cout << "num_wires: " << num_wires << "\n";

  // Precompute mapped symbols
  std::vector<uint32_t> pmap(opt.pattern_size);
  for (uint64_t j = 0; j < opt.pattern_size; ++j) pmap[j] = sym_val(pattern[j], opt.ring_size);

  std::vector<std::vector<uint32_t>> tmap(num_simd, std::vector<uint32_t>(opt.pattern_size));
  for (uint64_t i = 0; i < num_simd; ++i) {
    for (uint64_t j = 0; j < opt.pattern_size; ++j) {
      tmap[i][j] = sym_val(text[i + j], opt.ring_size);
    }
  }

  BooleanBEAVYWireVector wires;
  wires.reserve(num_wires);

  for (uint64_t j = 0; j < opt.pattern_size; ++j) {
    const auto pj = pmap[j];
    for (uint64_t r = 0; r < opt.ring_size; ++r) {
      ENCRYPTO::BitVector<> bits(num_simd, false);
      if (r == pj) {
        for (uint64_t i = 0; i < num_simd; ++i) {
          bits.Set(i, tmap[i][j] == pj);
        }
      }
      auto w = std::make_shared<BooleanBEAVYWire>(num_simd);
      // constant cleartext: secret 0, public = bits
      w->get_secret_share() = ENCRYPTO::BitVector<>(num_simd, false);
      w->get_public_share() = std::move(bits);
      w->set_setup_ready();
      w->set_online_ready();
      wires.push_back(std::move(w));
    }
  }

  return cast_wires(wires);
}

// Build *synthetic* BooleanBEAVY inputs (random shares) with the correct shape.
static WireVector make_boolean_inputs_for_pm_random(const Options& opt) {
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
    w->get_secret_share() = std::move(mx);
    w->get_public_share() = std::move(dx);
    w->set_setup_ready();
    w->set_online_ready();
    wires.push_back(std::move(w));
  }
  return cast_wires(wires);
}

// RHS parameter wire for EQEXP (gate reads public[0] as vec_size).
static std::vector<MOTION::NewWireP> make_eqexp_rhs_wire(const Options& opt) {
  const auto num_simd = opt.text_size - opt.pattern_size + 1;
  const auto num_wires = opt.pattern_size * opt.ring_size;
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
  return std::make_unique<MOTION::Communication::CommunicationLayer>(
      opt.my_id, helper.setup_connections());
}

static void print_phase(const char* name,
                        std::chrono::steady_clock::duration dur,
                        const CommDelta& c,
                        long rss_kb,
                        std::size_t run_idx,
                        std::size_t run_total) {
  using namespace std::chrono;
  std::cout << "[PHASE][" << run_idx+1 << "/" << run_total << "] " << name
            << " | ms=" << duration_cast<milliseconds>(dur).count()
            << " | bytes_sent=" << c.bytes_sent
            << " | bytes_recv=" << c.bytes_recv
            << " | msgs_sent="  << c.msgs_sent
            << " | msgs_recv="  << c.msgs_recv
            << " | rounds≈"     << rounds_from(c)
            << " | rss_kb="     << rss_kb
            << std::endl;
}

static double extract_ms(const std::string& txt, const char* label) {
  std::regex re(std::string("^") + label + R"(\s+([0-9.]+)\s+ms)",
                std::regex::icase | std::regex::multiline);
  std::smatch m;
  if (std::regex_search(txt, m, re)) return std::stod(m[1]);
  return -1.0;
}

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

struct Agg {
  std::chrono::milliseconds secret_ms{0};
  std::chrono::milliseconds pre_ms{0};
  std::chrono::milliseconds online_ms{0};
  CommDelta comm_pre{};
  CommDelta comm_online{};
  uint64_t rounds_pre_sum{0};
  uint64_t rounds_online_sum{0};
  MOTION::Statistics::AccumulatedRunTimeStats run_time_stats;
  MOTION::Statistics::AccumulatedCommunicationStats comm_stats;
};

// ------------------------ CLI ------------------------
static std::optional<Options> parse_cli(int argc, char** argv) {
  Options opt;
  po::options_description desc("Exact PM (assessed, sequential) options");
  desc.add_options()
    ("help,h", po::bool_switch()->default_value(false), "Show help")
    ("my-id", po::value<std::size_t>()->required(), "My party id (0 or 1)")
    ("party", po::value<std::vector<std::string>>()->multitoken()->required(),
       "(id,host,port) for both parties, e.g. --party 0,127.0.0.1,7002 --party 1,127.0.0.1,7003")
    ("threads", po::value<std::size_t>()->default_value(0), "Worker threads for backend")
    ("json", po::bool_switch()->default_value(false), "Print final MOTION stats in JSON")
    ("repetitions", po::value<std::size_t>()->default_value(1), "Outer repetitions")
    ("sync-between-setup-and-online", po::bool_switch()->default_value(false),
       "Insert a sync point between preprocessing and online")
    ("pattern-size", po::value<std::uint64_t>()->default_value(10), "Pattern length")
    ("text-size", po::value<std::uint64_t>()->default_value(256), "Text length")
    ("ring-size", po::value<std::uint64_t>()->default_value(16), "Alphabet/ring size")
    ("alpha-patterns", po::bool_switch()->default_value(true), "Use a-z generator")
    ("num-patterns", po::value<std::size_t>()->default_value(1024), "Number of runs")
    ("patt-seed", po::value<uint64_t>()->default_value(123456), "Pattern seed")
    ("text-seed", po::value<uint64_t>()->default_value(654321), "Text seed")
    ("per-run-log", po::bool_switch()->default_value(true), "Print 3 phases per run")
    ("feed-generated", po::bool_switch()->default_value(false),
       "Deterministically feed generated text/pattern into BEAVY wires (no reveal)")
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
  opt.per_run_log = vm["per-run-log"].as<bool>();
  opt.feed_generated = vm["feed-generated"].as<bool>();

  if (opt.pattern_size >= opt.text_size) {
    std::cerr << "pattern-size must be < text-size\n";
    return std::nullopt;
  }
  return opt;
}

// ------------------------ main ------------------------
int main(int argc, char** argv) {
  std::cerr << "[exact_pm_assessed HAM+EQEXP wrapper seq] " __DATE__ " " __TIME__ << std::endl;
  auto opt = parse_cli(argc, argv);
  if (!opt) return 1;

  try {
    // (A) Generate data (used only if --feed-generated)
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

    Agg agg;

    const std::size_t total_runs = opt->num_patterns * std::max<std::size_t>(1, opt->repetitions);
    std::size_t run_idx = 0;

    for (std::size_t rep = 0; rep < opt->repetitions; ++rep) {
      for (std::size_t p = 0; p < opt->num_patterns; ++p, ++run_idx) {

        // ===== (i) Local input prep
        const auto rss0 = get_rss_kb();
        const auto t0 = Clock::now();

        // Feed Generated text - pattern into 
        WireVector in_bool;
        if (opt->feed_generated && opt->alpha_patterns) {
          const auto& patt = pats.empty() ? std::string(opt->pattern_size, 'a') : pats[p];
          const auto& txt  = text.empty() ? std::string(opt->text_size, 'a') : text;
          in_bool = make_boolean_inputs_for_pm_from_data(*opt, txt, patt);
          std::cerr << "Using generated pattern (p=" << p << ")\n";
        } else {
          in_bool = make_boolean_inputs_for_pm_random(*opt);
        }

        const auto in_rhs  = make_eqexp_rhs_wire(*opt);

        const auto t1 = Clock::now();
        const auto secret_share_dur = t1 - t0;
        agg.secret_ms += std::chrono::duration_cast<std::chrono::milliseconds>(secret_share_dur);

        // ===== Backend per run => 
        MOTION::TwoPartyBackend backend(*comm, opt->threads,
                                        opt->sync_between_setup_and_online, logger);

        auto& gf_bool  = backend.get_gate_factory(MOTION::MPCProtocol::BooleanBEAVY);
        auto& gf_arith = backend.get_gate_factory(MOTION::MPCProtocol::ArithmeticBEAVY);

        // Circuit: HAM -> EQEXP
        auto ham = gf_bool.make_unary_gate(ENCRYPTO::PrimitiveOperationType::HAM, in_bool);
        (void)gf_arith.make_binary_gate(ENCRYPTO::PrimitiveOperationType::EQEXP, ham, in_rhs);

        // ===== (ii) Preprocessing + (iii) Online
        auto hook = std::make_shared<SplitObserver>(*comm);
        hook->t_pre_start = Clock::now();
        comm->reset_transport_statistics();
        backend.set_phase_observer(hook);

        const auto t_run_start = Clock::now();
        backend.run();
        const auto t_run_end   = Clock::now();

        const auto comm_online = get_comm_delta_and_reset(*comm);

        // Per-run logs
        if (opt->per_run_log) {
          print_phase("secret_share", secret_share_dur, {/*no comm*/0,0,0,0}, rss0, run_idx, total_runs);

          if (!hook->got_pre) {
            std::cerr << "[WARN][" << (run_idx+1) << "/" << total_runs
                      << "] PhaseObserver did not fire; cannot split preprocessing/online precisely.\n";
          }
          const auto pre_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                                hook->t_pre_end - hook->t_pre_start);
          print_phase("preprocessing", pre_ms, hook->comm_pre, get_rss_kb(), run_idx, total_runs);

          const auto online_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                                   t_run_end - hook->t_pre_end);
          print_phase("online", online_ms, comm_online, get_rss_kb(), run_idx, total_runs);
        }

        // Aggregate
        {
          const auto pre_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                                hook->t_pre_end - hook->t_pre_start);
          const auto online_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                                   t_run_end - hook->t_pre_end);
          agg.pre_ms    += pre_ms;
          agg.online_ms += online_ms;

          agg.comm_pre.bytes_sent += hook->comm_pre.bytes_sent;
          agg.comm_pre.bytes_recv += hook->comm_pre.bytes_recv;
          agg.comm_pre.msgs_sent  += hook->comm_pre.msgs_sent;
          agg.comm_pre.msgs_recv  += hook->comm_pre.msgs_recv;
          agg.rounds_pre_sum      += rounds_from(hook->comm_pre);

          agg.comm_online.bytes_sent += comm_online.bytes_sent;
          agg.comm_online.bytes_recv += comm_online.bytes_recv;
          agg.comm_online.msgs_sent  += comm_online.msgs_sent;
          agg.comm_online.msgs_recv  += comm_online.msgs_recv;
          agg.rounds_online_sum      += rounds_from(comm_online);

          agg.run_time_stats.add(backend.get_run_time_stats());
        }

        comm->sync();
        comm->reset_transport_statistics();
      }
    }

    // ===== Summary =====
    {
      using std::cout;
      using std::endl;
      const auto runs = static_cast<double>(total_runs);
      cout << "==================== SUMMARY over " << total_runs << " runs ====================\n";
      cout << "[secret_share]  total_ms=" << agg.secret_ms.count()
           << " | avg_ms=" << (agg.secret_ms.count()/runs) << "\n";
      cout << "[preprocessing] total_ms=" << agg.pre_ms.count()
           << " | avg_ms=" << (agg.pre_ms.count()/runs)
           << " | bytes_sent=" << agg.comm_pre.bytes_sent
           << " | bytes_recv=" << agg.comm_pre.bytes_recv
           << " | msgs_sent="  << agg.comm_pre.msgs_sent
           << " | msgs_recv="  << agg.comm_pre.msgs_recv
           << " | rounds_sum≈" << agg.rounds_pre_sum
           << " | rounds_avg≈" << (static_cast<double>(agg.rounds_pre_sum)/runs) << "\n";
      cout << "[online]        total_ms=" << agg.online_ms.count()
           << " | avg_ms=" << (agg.online_ms.count()/runs)
           << " | bytes_sent=" << agg.comm_online.bytes_sent
           << " | bytes_recv=" << agg.comm_online.bytes_recv
           << " | msgs_sent="  << agg.comm_online.msgs_sent
           << " | msgs_recv="  << agg.comm_online.msgs_recv
           << " | rounds_sum≈" << agg.rounds_online_sum
           << " | rounds_avg≈" << (static_cast<double>(agg.rounds_online_sum)/runs) << "\n";

      const auto stats_txt = MOTION::Statistics::print_stats("Exact Pattern Matching",
                                                             agg.run_time_stats, agg.comm_stats);
      const double ms_prep_total   = extract_ms(stats_txt, "Preprocessing Total");
      const double ms_gates_setup  = extract_ms(stats_txt, "Gates Setup");
      const double ms_gates_online = extract_ms(stats_txt, "Gates Online");
      cout << "[MOTION] preprocessing_ms=" << ms_prep_total
           << " | gates_setup_ms=" << ms_gates_setup
           << " | gates_online_ms=" << ms_gates_online << endl;
      cout << "===============================================================================\n";
    }

    comm->shutdown();
  } catch (const std::exception& e) {
    std::cerr << "ERROR: " << e.what() << "\n";
    return 2;
  }
  return 0;
}
