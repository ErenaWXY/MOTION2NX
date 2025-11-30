// MIT License
//
// Copyright (c) 2021 Lennart Braun
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

#include <algorithm>
#include <cmath>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <random>
#include <regex>
#include <stdexcept>
#include <chrono>
#include <optional>
#include <cstdint>

#include <boost/algorithm/string.hpp>
#include <boost/json/serialize.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/log/trivial.hpp>
#include <boost/program_options.hpp>

#include "algorithm/circuit_loader.h"
#include "base/gate_factory.h"
#include "base/two_party_backend.h"
#include "communication/communication_layer.h"
#include "communication/tcp_transport.h"
#include "communication/message_handler.h"  // QueueHandler
#include "statistics/analysis.h"
#include "utility/logger.h"
#include "utility/bit_vector.h"
#include "protocols/beavy/beavy_provider.cpp"
#include "wire/new_wire.h"
#include "utility/helpers.h"

#include "protocols/gmw/wire.h"
#include "protocols/gmw/gate.h"
#include "protocols/gmw/gmw_provider.h"
#include "utility/bit_vector.h"
#include "protocols/gmw/gmw_provider.cpp"

namespace po = boost::program_options;
using namespace MOTION::proto::gmw;
using NewWire = MOTION::NewWire;
using WireVector = std::vector<std::shared_ptr<NewWire>>;

struct Options {
  std::size_t threads;
  bool json;
  std::size_t num_repetitions;
  std::size_t num_simd;
  bool sync_between_setup_and_online;
  MOTION::MPCProtocol arithmetic_protocol;
  MOTION::MPCProtocol boolean_protocol;
  std::uint64_t pattern_size;
  std::uint64_t text_size;
  // Note: we implicitly use Z_256 (uint8_t) as ring for secret-sharing.
  std::size_t my_id;
  MOTION::Communication::tcp_parties_config tcp_config;
  bool no_run = false;
};

std::optional<Options> parse_program_options(int argc, char* argv[]) {
  Options options;
  boost::program_options::options_description desc("Allowed options");
  // clang-format off
  desc.add_options()
    ("help,h", po::bool_switch()->default_value(false),"produce help message")
    ("config-file", po::value<std::string>(), "config file containing options")
    ("my-id", po::value<std::size_t>()->required(), "my party id")
    ("party", po::value<std::vector<std::string>>()->multitoken(),
     "(party id, IP, port), e.g., --party 1,127.0.0.1,7777")
    ("threads", po::value<std::size_t>()->default_value(0), "number of threads to use for gate evaluation")
    ("json", po::bool_switch()->default_value(false), "output data in JSON format")
    ("pattern-size", po::value<std::uint64_t>()->required(), "size of pattern")
    ("text-size", po::value<std::uint64_t>()->required(), "size of text")
    // ("ring-size", po::value<std::size_t>()->default_value(16), "size of the ring")
    ("repetitions", po::value<std::size_t>()->default_value(1), "number of repetitions")
    ("num-simd", po::value<std::size_t>()->default_value(1), "number of SIMD values")
    ("sync-between-setup-and-online", po::bool_switch()->default_value(false),
     "run a synchronization protocol before the online phase starts")
    ("no-run", po::bool_switch()->default_value(false), "just build the circuit, but not execute it")
    ;
  // clang-format on

  po::variables_map vm;
  po::store(po::parse_command_line(argc, argv, desc), vm);
  bool help = vm["help"].as<bool>();
  if (help) {
    std::cerr << desc << "\n";
    return std::nullopt;
  }
  if (vm.count("config-file")) {
    std::ifstream ifs(vm["config-file"].as<std::string>().c_str());
    po::store(po::parse_config_file(ifs, desc), vm);
  }
  try {
    po::notify(vm);
  } catch (std::exception& e) {
    std::cerr << "error:" << e.what() << "\n\n";
    std::cerr << desc << "\n";
    return std::nullopt;
  }

  options.my_id = vm["my-id"].as<std::size_t>();
  options.threads = vm["threads"].as<std::size_t>();
  options.json = vm["json"].as<bool>();
  options.num_repetitions = vm["repetitions"].as<std::size_t>();
  options.num_simd = vm["num-simd"].as<std::size_t>();
  options.sync_between_setup_and_online = vm["sync-between-setup-and-online"].as<bool>();
  options.no_run = vm["no-run"].as<bool>();

  options.arithmetic_protocol = MOTION::MPCProtocol::ArithmeticGMW;
  options.boolean_protocol = MOTION::MPCProtocol::BooleanGMW;

  auto pattern_size = vm["pattern-size"].as<std::uint64_t>();
  options.pattern_size = vm["pattern-size"].as<std::uint64_t>();
  

  auto text_size = vm["text-size"].as<std::uint64_t>();
  options.text_size = text_size;
  assert(pattern_size < text_size);

  const auto parse_party_argument =
      [](const auto& s) -> std::pair<std::size_t, MOTION::Communication::tcp_connection_config> {
    const static std::regex party_argument_re("([012]),([^,]+),(\\d{1,5})");
    std::smatch match;
    if (!std::regex_match(s, match, party_argument_re)) {
      throw std::invalid_argument("invalid party argument");
    }
    auto id = boost::lexical_cast<std::size_t>(match[1]);
    auto host = match[2];
    auto port = boost::lexical_cast<std::uint16_t>(match[3]);
    return {id, {host, port}};
  };

  const std::vector<std::string> party_infos = vm["party"].as<std::vector<std::string>>();
  if (party_infos.size() != 2) {
    std::cerr << "expecting two --party options\n";
    return std::nullopt;
  }

  options.tcp_config.resize(2);


  const auto [id0, conn_info0] = parse_party_argument(party_infos[0]);
  const auto [id1, conn_info1] = parse_party_argument(party_infos[1]);
  if (id0 == id1) {
    std::cerr << "need party arguments for party 0 and 1\n";
    return std::nullopt;
  }
  options.tcp_config[id0] = conn_info0;
  options.tcp_config[id1] = conn_info1;

  return options;
}


std::unique_ptr<MOTION::Communication::CommunicationLayer> setup_communication(
    const Options& options) {
  MOTION::Communication::TCPSetupHelper helper(options.my_id, options.tcp_config);
  return std::make_unique<MOTION::Communication::CommunicationLayer>(options.my_id,
                                                                     helper.setup_connections());
}

// Helper from original file (unused but kept to minimize diff)
std::vector<uint64_t> convert_to_binary(uint64_t x) {
    std::vector<uint64_t> res;
    for (uint64_t i = 0; i < 64; ++i) {
        if (x%2 == 1) res.push_back(1);
        else res.push_back(0);
        x /= 2;
    }
    return res;
}

// ---------------------------------------------------------------------------
// Phase 1: Secret-sharing of raw inputs (only shares are kept)
//
// We simulate the paper-style setting:
//  - Party 0 holds a private text T[0..n-1] (generated randomly here),
//  - Party 1 holds a private pattern P[0..m-1] (generated randomly here).
//
// Each value (uint8_t) is secret-shared additively over Z_256.
// We only keep the *shares* locally; plaintext T and P are not used later.
// ---------------------------------------------------------------------------

struct SecretSharingStats {
  double total_ms = 0.0;
  std::uint64_t bytes_sent = 0;
  std::uint64_t bytes_recv = 0;
};

struct LocalShares {
  // From the perspective of THIS party:
  //  - text_share: share of the text
  //  - pattern_share: share of the pattern
  std::vector<std::uint8_t> text_share;
  std::vector<std::uint8_t> pattern_share;
  SecretSharingStats stats;
};

LocalShares run_secret_sharing_phase(const Options& options,
                                     MOTION::Communication::CommunicationLayer& cl) {
  using namespace std::chrono;

  LocalShares ls;
  const std::size_t n = options.text_size;
  const std::size_t m = options.pattern_size;

  cl.reset_transport_statistics();

  const std::size_t my_id    = options.my_id;
  const std::size_t other_id = 1 - my_id;

  // Use QueueHandler as fallback to receive raw byte messages (shares).
  auto& qh_other =
      dynamic_cast<MOTION::Communication::QueueHandler&>(
          cl.get_fallback_message_handler(other_id));

  std::mt19937_64 rng(0xC0FFEEULL ^ static_cast<std::uint64_t>(my_id));
  std::uniform_int_distribution<int> dist(0, 255);

  auto t0 = steady_clock::now();

  if (my_id == 0) {
    // Party 0:
    //   - generates private text T[0..n-1] (local),
    //   - shares it additively: T[i] = s0[i] + s1[i] (mod 256 = 2^8),
    //   - keeps s0[i] locally, sends s1[i] to party 1,
    //   - receives a share of the pattern from party 1.

    std::vector<std::uint8_t> my_text_share(n);
    std::vector<std::uint8_t> other_text_share(n);

    for (std::size_t i = 0; i < n; ++i) {
      // local plaintext text[i] (never stored globally)
      auto t_i = static_cast<std::uint8_t>(dist(rng));
      auto r_i = static_cast<std::uint8_t>(dist(rng));  // random share

      my_text_share[i] = r_i;
      int diff = static_cast<int>(t_i) - static_cast<int>(r_i);
      if (diff < 0) diff += 256;
      other_text_share[i] = static_cast<std::uint8_t>(diff);
    }

    ls.text_share = my_text_share;

    // Send text shares to party 1
    cl.send_message(other_id, std::move(other_text_share));

    // Receive pattern share from party 1
    auto recv_pattern_opt = qh_other.get_queue().dequeue();
    if (!recv_pattern_opt.has_value()) {
      throw std::runtime_error("Party 0: expected pattern share message");
    }
    auto& recv_pattern_share = recv_pattern_opt.value();
    if (recv_pattern_share.size() != m) {
      throw std::runtime_error("Party 0: received pattern share size mismatch");
    }
    ls.pattern_share = recv_pattern_share;

  } else {
    // Party 1:
    //   - generates private pattern P[0..m-1] (local),
    //   - shares it additively: P[j] = t0[j] + t1[j] (mod 256 = 2^8),
    //   - keeps one share locally, sends the other to party 0,
    //   - receives a share of the text from party 0.

    std::vector<std::uint8_t> my_pattern_share(m);
    std::vector<std::uint8_t> other_pattern_share(m);

    for (std::size_t j = 0; j < m; ++j) {
      // local plaintext pattern[j] (never stored globally)
      auto p_j = static_cast<std::uint8_t>(dist(rng));
      auto r_j = static_cast<std::uint8_t>(dist(rng));  // random share

      my_pattern_share[j] = r_j;
      int diff = static_cast<int>(p_j) - static_cast<int>(r_j);
      if (diff < 0) diff += 256;
      other_pattern_share[j] = static_cast<std::uint8_t>(diff);
    }

    ls.pattern_share = my_pattern_share;

    // Send pattern shares to party 0
    cl.send_message(other_id, std::move(other_pattern_share));

    // Receive text share from party 0
    auto recv_text_opt = qh_other.get_queue().dequeue();
    if (!recv_text_opt.has_value()) {
      throw std::runtime_error("Party 1: expected text share message");
    }
    auto& recv_text_share = recv_text_opt.value();
    if (recv_text_share.size() != n) {
      throw std::runtime_error("Party 1: received text share size mismatch");
    }
    ls.text_share = recv_text_share;
  }

  cl.sync();

  auto t1 = steady_clock::now();
  ls.stats.total_ms =
      std::chrono::duration_cast<std::chrono::duration<double, std::milli>>(t1 - t0).count();

  auto stats_vec = cl.get_transport_statistics();
  for (const auto& st : stats_vec) {
    ls.stats.bytes_sent += st.num_bytes_sent;
    ls.stats.bytes_recv += st.num_bytes_received;
  }

  return ls;
}

// ---------------------------------------------------------------------------
// Phase 2: Derive HAM / DPF inputs *from local shares*
//
// We purposely do NOT use the original plaintext text/pattern anymore.
// Instead, each party treats its local shares as "effective text/pattern"
// (text_share and pattern_share) and computes:
//    ham_vec[i] = Hamming(text_share[i..i+m-1], pattern_share[0..m-1])
//    dpf_vec[i] = 1_{ham_vec[i] == 0}
// ---------------------------------------------------------------------------
struct PMValues {
  std::vector<std::uint8_t> ham_vec;
  std::vector<std::uint8_t> dpf_vec;
};

PMValues compute_ham_and_dpf_inputs_from_shares(const Options& options,
                                                const LocalShares& ls) {
  PMValues v;

  const std::size_t n = ls.text_share.size();
  const std::size_t m = ls.pattern_share.size();

  if (n != options.text_size || m != options.pattern_size) {
    throw std::runtime_error("LocalShares sizes do not match Options");
  }

  const std::size_t num_simd = n - m + 1;
  v.ham_vec.resize(num_simd);
  v.dpf_vec.resize(num_simd);

  for (std::size_t i = 0; i < num_simd; ++i) {
    std::uint8_t ham = 0;
    for (std::size_t j = 0; j < m; ++j) {
      if (ls.text_share[i + j] != ls.pattern_share[j]) {
        ++ham;
      }
    }
    v.ham_vec[i] = ham;
    v.dpf_vec[i] = static_cast<std::uint8_t>(ham == 0 ? 1 : 0);
  }

  return v;
}

// ---------------------------------------------------------------------------
// Original helper for DPF input (now unused, but kept to minimize diff)
//
// auto make_dpf_in_wire(const Options& options) { ... }
//
// ---------------------------------------------------------------------------
auto make_dpf_in_wire(const Options& options) {
  
  auto num_simd = (options.text_size - options.pattern_size + 1);
  auto num_wires = options.pattern_size;

  auto wire = std::make_shared<ArithmeticGMWWire<uint8_t>>(num_simd);
  std::vector<MOTION::NewWireP> in;
  std::vector<uint8_t> x(num_simd, 2*num_wires);

  wire->get_share() = x;
  wire->set_online_ready();

  in.push_back(wire);
  return in;
}

// ---------------------------------------------------------------------------
// Original helper for HAM input (now unused, but kept to minimize diff)
//
// auto make_ham_in_wire(const Options& options) { ... }
//
// ---------------------------------------------------------------------------
auto make_ham_in_wire(const Options& options) {

  auto num_simd = (options.text_size - options.pattern_size + 1);

  auto wire = std::make_shared<ArithmeticGMWWire<uint32_t>>(num_simd);
  std::vector<MOTION::NewWireP> in;
  std::vector<uint32_t> x(num_simd, 1);

  wire->get_share() = x;
  wire->set_online_ready();

  in.push_back(wire);
  return in;
}

// ---------------------------------------------------------------------------
// New helpers: build GMW input wires from share-based HAM/DPF vectors
// ---------------------------------------------------------------------------
WireVector make_ham_in_wire_from_values(const Options& options,
                                        const std::vector<std::uint8_t>& ham_vec) {
  const auto num_simd = options.text_size - options.pattern_size + 1;
  if (ham_vec.size() != num_simd) {
    throw std::runtime_error("ham_vec size mismatch");
  }

  // We can store HAM values in uint8_t here as well
  auto wire = std::make_shared<ArithmeticGMWWire<std::uint8_t>>(num_simd);
  std::vector<MOTION::NewWireP> in;

  wire->get_share() = ham_vec;
  wire->set_online_ready();

  in.push_back(wire);
  return in;
}

WireVector make_dpf_in_wire_from_values(const Options& options,
                                        const std::vector<std::uint8_t>& dpf_vec) {
  const auto num_simd = options.text_size - options.pattern_size + 1;
  if (dpf_vec.size() != num_simd) {
    throw std::runtime_error("dpf_vec size mismatch");
  }

  auto wire = std::make_shared<ArithmeticGMWWire<std::uint8_t>>(num_simd);
  std::vector<MOTION::NewWireP> in;

  wire->get_share() = dpf_vec;
  wire->set_online_ready();

  in.push_back(wire);
  return in;
}

// ---------------------------------------------------------------------------
// Circuit run (kept as in your requested version: HAM + DPF)
// ---------------------------------------------------------------------------
void run_circuit(const Options& options, MOTION::TwoPartyBackend& backend, WireVector in1, WireVector in2) {

  if (options.no_run) {
    return;
  }

  MOTION::MPCProtocol arithmetic_protocol = options.arithmetic_protocol;
  MOTION::MPCProtocol boolean_protocol = options.boolean_protocol;
  auto& gate_factory_arith = backend.get_gate_factory(arithmetic_protocol);
  auto& gate_factory_bool = backend.get_gate_factory(boolean_protocol);

  auto output1 = gate_factory_bool.make_unary_gate(ENCRYPTO::PrimitiveOperationType::HAM, in1);
  auto output = gate_factory_arith.make_unary_gate(
    ENCRYPTO::PrimitiveOperationType::DPF, in2);

  (void)output1;
  (void)output;

  backend.run();

}

// ---------------------------------------------------------------------------
// Printing statistics
// ---------------------------------------------------------------------------
void print_stats(const Options& options,
                 const MOTION::Statistics::AccumulatedRunTimeStats& run_time_stats,
                 const MOTION::Statistics::AccumulatedCommunicationStats& comm_stats) {
  if (options.json) {
    auto obj = MOTION::Statistics::to_json("exact_pm", run_time_stats, comm_stats);
    obj.emplace("party_id", options.my_id);
    obj.emplace("threads", options.threads);
    obj.emplace("sync_between_setup_and_online", options.sync_between_setup_and_online);
    std::cout << obj << "\n";
  } else {
    std::cout << MOTION::Statistics::print_stats("Exact Pattern Matching", run_time_stats,
                                                 comm_stats);
  }
}

void print_stats_secret_sharing(const Options& options,
                                const SecretSharingStats& s) {
  const double kib_sent = static_cast<double>(s.bytes_sent) / 1024.0;
  const double kib_recv = static_cast<double>(s.bytes_recv) / 1024.0;

  std::cout << "================ Secret Sharing (raw input, Z_256) =====================\n";
  std::cout << "Party " << options.my_id << ":\n";
  std::cout << "  Text size n      = " << options.text_size  << "\n";
  std::cout << "  Pattern size m   = " << options.pattern_size << "\n";
  std::cout << "  Repetitions      = " << options.num_repetitions << "\n";
  std::cout << "--------------------------------------------------------------------------\n";
  std::cout << "  Total time       = " << s.total_ms << " ms\n";
  std::cout << "  Avg time / rep   = " << (s.total_ms / options.num_repetitions)
            << " ms\n";
  std::cout << "  Total bytes sent = " << s.bytes_sent
            << " (" << kib_sent << " KiB)\n";
  std::cout << "  Total bytes recv = " << s.bytes_recv
            << " (" << kib_recv << " KiB)\n";
  std::cout << "  Avg sent / rep   = "
            << static_cast<double>(s.bytes_sent) / options.num_repetitions
            << " bytes (" << kib_sent / options.num_repetitions << " KiB)\n";
  std::cout << "  Avg recv / rep   = "
            << static_cast<double>(s.bytes_recv) / options.num_repetitions
            << " bytes (" << kib_recv / options.num_repetitions << " KiB)\n";
  std::cout << "==========================================================================\n";
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------
int main(int argc, char* argv[]) {
  auto options = parse_program_options(argc, argv);

  if (!options.has_value()) {
    return EXIT_FAILURE;
  }

  try {

    auto comm_layer = setup_communication(*options);
    auto logger = std::make_shared<MOTION::Logger>(options->my_id,
                                                   boost::log::trivial::severity_level::trace);
    comm_layer->set_logger(logger);

    // Fallback handler for "raw share" messages in Phase 1
    comm_layer->register_fallback_message_handler(
        [](auto /*party_id*/) {
          return std::make_shared<MOTION::Communication::QueueHandler>();
        });

    comm_layer->start();

    // Phase 1: secret-share raw inputs (only shares are kept)
    LocalShares local_shares = run_secret_sharing_phase(*options, *comm_layer);

    // Phase 2: derive HAM/DPF input vectors from the local shares
    PMValues pm_values = compute_ham_and_dpf_inputs_from_shares(*options, local_shares);

    MOTION::Statistics::AccumulatedRunTimeStats run_time_stats;
    MOTION::Statistics::AccumulatedCommunicationStats comm_stats;

    for (std::size_t i = 0; i < options->num_repetitions; ++i) {
      comm_layer->reset_transport_statistics();

      MOTION::TwoPartyBackend backend(*comm_layer, options->threads,
                                      options->sync_between_setup_and_online, logger);

      // Build GMW input wires from the share-based HAM / DPF vectors
      auto in1 = make_ham_in_wire_from_values(*options, pm_values.ham_vec);
      auto in2 = make_dpf_in_wire_from_values(*options, pm_values.dpf_vec);

      run_circuit(*options, backend, in1, in2);
      comm_layer->sync();
      comm_stats.add(comm_layer->get_transport_statistics());
      comm_layer->reset_transport_statistics();
      run_time_stats.add(backend.get_run_time_stats());
    }
    comm_layer->shutdown();
    print_stats(*options, run_time_stats, comm_stats);
    print_stats_secret_sharing(*options, local_shares.stats);
  } catch (std::runtime_error& e) {
    std::cerr << "ERROR OCCURRED: " << e.what() << "\n";
    return EXIT_FAILURE;
  }

  return EXIT_SUCCESS;
}