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
#include <cassert>
#include <cmath>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <optional>
#include <random>
#include <regex>
#include <stdexcept>
#include <string>
#include <vector>

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
#include "statistics/analysis.h"
#include "utility/logger.h"
#include "utility/bit_vector.h"
#include "utility/helpers.h"
#include "wire/new_wire.h"

// GMW
#include "protocols/gmw/wire.h"
#include "protocols/gmw/gate.h"
#include "protocols/gmw/gmw_provider.h"
#include "protocols/gmw/gmw_provider.cpp"

// BEAVY provider cpp is included only to satisfy linker in this branch
#include "protocols/beavy/beavy_provider.cpp"

namespace po = boost::program_options;
using namespace MOTION::proto::gmw;

using NewWire    = MOTION::NewWire;
using WireVector = std::vector<std::shared_ptr<NewWire>>;

struct Options {
  std::size_t threads;
  bool json;
  std::size_t num_repetitions;
  std::size_t num_simd;  // kept for compatibility; not used
  bool sync_between_setup_and_online;
  MOTION::MPCProtocol arithmetic_protocol;
  MOTION::MPCProtocol boolean_protocol;
  std::uint64_t pattern_size;
  std::uint64_t text_size;
  std::size_t my_id;
  MOTION::Communication::tcp_parties_config tcp_config;
  bool no_run = false;
};

std::optional<Options> parse_program_options(int argc, char* argv[]) {
  Options options;
  po::options_description desc("Allowed options");
  // clang-format off
  desc.add_options()
    ("help,h", po::bool_switch()->default_value(false), "produce help message")
    ("config-file", po::value<std::string>(), "config file containing options")
    ("my-id", po::value<std::size_t>()->required(), "my party id")
    ("party", po::value<std::vector<std::string>>()->multitoken(),
      "(party id, IP, port), e.g., --party 0,127.0.0.1,7002 --party 1,127.0.0.1,7003")
    ("threads", po::value<std::size_t>()->default_value(0),
      "number of threads to use for gate evaluation")
    ("json", po::bool_switch()->default_value(false),
      "output data in JSON format")
    ("pattern-size", po::value<std::uint64_t>()->required(), "size of pattern")
    ("text-size", po::value<std::uint64_t>()->required(), "size of text")
    ("repetitions", po::value<std::size_t>()->default_value(1),
      "number of repetitions")
    ("num-simd", po::value<std::size_t>()->default_value(1),
      "number of SIMD values (ignored)")
    ("sync-between-setup-and-online", po::bool_switch()->default_value(false),
      "run a synchronization protocol before the online phase starts")
    ("no-run", po::bool_switch()->default_value(false),
      "just build the circuit, but not execute it")
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

  options.my_id   = vm["my-id"].as<std::size_t>();
  options.threads = vm["threads"].as<std::size_t>();
  options.json    = vm["json"].as<bool>();
  options.num_repetitions = vm["repetitions"].as<std::size_t>();
  options.num_simd        = vm["num-simd"].as<std::size_t>();
  options.sync_between_setup_and_online =
      vm["sync-between-setup-and-online"].as<bool>();
  options.no_run = vm["no-run"].as<bool>();

  options.arithmetic_protocol = MOTION::MPCProtocol::ArithmeticGMW;
  options.boolean_protocol    = MOTION::MPCProtocol::BooleanGMW;

  options.pattern_size = vm["pattern-size"].as<std::uint64_t>();
  options.text_size    = vm["text-size"].as<std::uint64_t>();

  if (!(options.pattern_size < options.text_size)) {
    throw std::invalid_argument("pattern-size must be < text-size");
  }

  const auto parse_party_argument =
      [](const auto& s)
      -> std::pair<std::size_t, MOTION::Communication::tcp_connection_config> {
    const static std::regex party_argument_re("([01]),([^,]+),(\\d{1,5})");
    std::smatch match;
    if (!std::regex_match(s, match, party_argument_re)) {
      throw std::invalid_argument("invalid party argument");
    }
    auto id   = boost::lexical_cast<std::size_t>(match[1]);
    auto host = match[2];
    auto port = boost::lexical_cast<std::uint16_t>(match[3]);
    return {id, {host, port}};
  };

  const std::vector<std::string> party_infos =
      vm["party"].as<std::vector<std::string>>();
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

std::unique_ptr<MOTION::Communication::CommunicationLayer>
setup_communication(const Options& options) {
  MOTION::Communication::TCPSetupHelper helper(options.my_id,
                                               options.tcp_config);
  return std::make_unique<MOTION::Communication::CommunicationLayer>(
      options.my_id, helper.setup_connections());
}

// ===========================================================================
// Phase 0: Plaintext inputs (outside MPC, only for encoding windows)
// ===========================================================================

struct PlainInputs {
  std::vector<std::uint8_t> text;
  std::vector<std::uint8_t> pattern;
};

// Generate deterministic plaintext text & pattern (same on both parties).
// If n=5, m=3 → use "HELLO" / "LLO" for easier debugging.
PlainInputs generate_plain_inputs(const Options& options) {
  PlainInputs in;
  in.text.resize(options.text_size);
  in.pattern.resize(options.pattern_size);

  if (options.text_size == 5 && options.pattern_size == 3) {
    const std::string txt = "HELLO";
    const std::string pat = "LLO";
    for (std::size_t i = 0; i < options.text_size; ++i) {
      in.text[i] = static_cast<std::uint8_t>(txt[i]);
    }
    for (std::size_t j = 0; j < options.pattern_size; ++j) {
      in.pattern[j] = static_cast<std::uint8_t>(pat[j]);
    }
    return in;
  }

  // Otherwise: deterministic random based on sizes (both parties get the same).
  std::mt19937_64 rng(0x51C0FFEEULL ^
                      static_cast<std::uint64_t>(options.text_size << 32) ^
                      static_cast<std::uint64_t>(options.pattern_size));
  std::uniform_int_distribution<int> dist(0, 255);

  for (auto& c : in.text) {
    c = static_cast<std::uint8_t>(dist(rng));
  }
  for (auto& c : in.pattern) {
    c = static_cast<std::uint8_t>(dist(rng));
  }
  return in;
}

// ===========================================================================
// Phase 1: Windowing before GMW
//
// Build windows T_i = T[i..i+m-1] with i = 0..n-m.
// Encode windows into a single flat vector windowed_text_flat:
//
//   index_flat = i * m + j  <=>  T_i[j] = text[i + j]
//
// This is done BEFORE we secret-share via GMW input gates.
// ===========================================================================

struct WindowedInputs {
  std::vector<std::uint8_t> windowed_text_flat;  // size = num_windows * m
  std::vector<std::uint8_t> pattern;             // size = m
  std::size_t num_windows;
};

WindowedInputs encode_windows(const Options& options,
                              const PlainInputs& plain) {
  const std::size_t n = static_cast<std::size_t>(options.text_size);
  const std::size_t m = static_cast<std::size_t>(options.pattern_size);
  assert(plain.text.size() == n);
  assert(plain.pattern.size() == m);

  const std::size_t num_windows = n - m + 1;
  WindowedInputs win;
  win.num_windows = num_windows;
  win.windowed_text_flat.resize(num_windows * m);
  win.pattern = plain.pattern;  // copy pattern as-is

  for (std::size_t i = 0; i < num_windows; ++i) {
    for (std::size_t j = 0; j < m; ++j) {
      std::size_t idx_flat = i * m + j;
      std::size_t idx_text = i + j;
      win.windowed_text_flat[idx_flat] = plain.text[idx_text];
    }
  }
  return win;
}

// ===========================================================================
// Phase 2: GMW input gates for windowed_text + pattern
//
// Windows are owned by Party 0, pattern is owned by Party 1.
// GMWProvider will secret-share both vectors internally; we only provide
// "my inputs" via promises.
// ===========================================================================

struct GMWInputHandles {
  // Promises for "my" inputs:
  //  - Party 0: windowed_text_flat
  //  - Party 1: pattern
  std::optional<ENCRYPTO::ReusableFiberPromise<MOTION::IntegerValues<std::uint8_t>>> my_window_promise;
  std::optional<ENCRYPTO::ReusableFiberPromise<MOTION::IntegerValues<std::uint8_t>>> my_pattern_promise;

  // Secret-shared wires as returned by the input gates (same shape on both parties):
  WireVector window_wires;   // arithmetic-8 wire for all windows (flattened)
  WireVector pattern_wires;  // arithmetic-8 wire for pattern
};

GMWInputHandles make_gmw_input_gates_for_windows(
    const Options& options,
    MOTION::GateFactory& gate_factory_arith,
    const WindowedInputs& win) {

  GMWInputHandles handles;

  const std::size_t m  = static_cast<std::size_t>(options.pattern_size);
  const std::size_t nw = win.num_windows;
  const std::size_t num_simd_windows = nw * m;  // flatten windows

  const std::size_t text_owner    = 0;
  const std::size_t pattern_owner = 1;

  if (options.my_id == 0) {
    // Party 0:
    //   - my arithmetic input: windowed_text_flat (size = num_windows * m)
    //   - other's arithmetic input: pattern (size = m)
    auto text_pair =
        gate_factory_arith.make_arithmetic_8_input_gate_my(text_owner,
                                                           num_simd_windows);
    handles.my_window_promise = std::move(text_pair.first);
    handles.window_wires      = std::move(text_pair.second);

    auto pattern_wires_other =
        gate_factory_arith.make_arithmetic_8_input_gate_other(pattern_owner,
                                                              m);
    handles.pattern_wires = std::move(pattern_wires_other);
  } else {
    // Party 1:
    //   - other's arithmetic input: windowed_text_flat
    //   - my arithmetic input: pattern
    auto text_wires_other =
        gate_factory_arith.make_arithmetic_8_input_gate_other(text_owner,
                                                              num_simd_windows);
    handles.window_wires = std::move(text_wires_other);

    auto pattern_pair =
        gate_factory_arith.make_arithmetic_8_input_gate_my(pattern_owner, m);
    handles.my_pattern_promise = std::move(pattern_pair.first);
    handles.pattern_wires      = std::move(pattern_pair.second);
  }

  return handles;
}

// Set the actual plaintext values for "my" inputs.
//  - Party 0: provides windowed_text_flat
//  - Party 1: provides pattern
void set_gmw_input_values(const Options& options,
                          const WindowedInputs& win,
                          GMWInputHandles& handles) {
  if (options.my_id == 0 && handles.my_window_promise.has_value()) {
    MOTION::IntegerValues<std::uint8_t> vals;
    vals = win.windowed_text_flat;  // flattened windows
    handles.my_window_promise->set_value(std::move(vals));
  }

  if (options.my_id == 1 && handles.my_pattern_promise.has_value()) {
    MOTION::IntegerValues<std::uint8_t> vals;
    vals = win.pattern;  // pattern
    handles.my_pattern_promise->set_value(std::move(vals));
  }
}

// ===========================================================================
// Phase 3: HAM + DPF built directly on secret-shared window wires
//
// At this stage, the wires in handles.window_wires are already secret-shared
// arithmetic-8 values representing the flattened windows T_i[j].
//
// We do NOT implement full "exact PM" yet. Instead:
//   • HAM is attached as a unary gate taking the window wires,
//   • DPF is attached similarly.
//
// This shows how to connect the secret-shared window wires into the
// existing primitive kernels (HAM/DPF), without touching plaintext.
// ===========================================================================

void attach_ham_dpf_on_window_shares(const Options& options,
                                     MOTION::TwoPartyBackend& backend,
                                     const GMWInputHandles& handles,
                                     const WindowedInputs& win) {
  (void)win;  // currently not needed inside this function

  if (handles.window_wires.empty()) {
    // Should not happen, but guard anyway.
    return;
  }

  auto& gate_factory_arith = backend.get_gate_factory(options.arithmetic_protocol);
  auto& gate_factory_bool  = backend.get_gate_factory(options.boolean_protocol);

  // Use the secret-shared window wires as inputs for both HAM and DPF.
  // Note:
  //  - Internal implementation of HAM/DPF will inspect the bit-size (8 here)
  //    and run the corresponding arithmetic GMW gates.
  //  - From the outside, we only need to pass the WireVector.
  WireVector ham_in  = handles.window_wires;
  WireVector dpf_in  = handles.window_wires;

  auto ham_out = gate_factory_bool.make_unary_gate(
      ENCRYPTO::PrimitiveOperationType::HAM, ham_in);

  auto dpf_out = gate_factory_arith.make_unary_gate(
      ENCRYPTO::PrimitiveOperationType::DPF, dpf_in);

  (void)ham_out;
  (void)dpf_out;
}

// ===========================================================================
// run_circuit:
//   1. Build GMW arithmetic-8 input gates for windowed_text_flat + pattern.
//   2. Set "my" input values (Party 0: windows, Party 1: pattern).
//   3. Attach HAM/DPF directly on the secret-shared window wires.
//   4. Run the MPC backend.
// ===========================================================================

void run_circuit(const Options& options,
                 MOTION::TwoPartyBackend& backend,
                 const WindowedInputs& win) {
  if (options.no_run) {
    return;
  }

  auto& gate_factory_arith = backend.get_gate_factory(options.arithmetic_protocol);

  // Phase 2: GMW input gates for windows + pattern.
  auto handles =
      make_gmw_input_gates_for_windows(options, gate_factory_arith, win);

  // Provide plaintext values only on the owning party.
  set_gmw_input_values(options, win, handles);

  // Phase 3: attach HAM + DPF gates on top of the secret-shared window wires.
  attach_ham_dpf_on_window_shares(options, backend, handles, win);

  // Execute full protocol (input sharing + HAM/DPF).
  backend.run();
}

// ===========================================================================
// Print stats
// ===========================================================================

void print_stats(const Options& options,
                 const MOTION::Statistics::AccumulatedRunTimeStats& run_time_stats,
                 const MOTION::Statistics::AccumulatedCommunicationStats& comm_stats) {
  if (options.json) {
    auto obj = MOTION::Statistics::to_json("exact_pm_windowed_gmw_ham_dpf", run_time_stats, comm_stats);
    obj.emplace("party_id", options.my_id);
    obj.emplace("threads", options.threads);
    obj.emplace("sync_between_setup_and_online",
                options.sync_between_setup_and_online);
    std::cout << obj << "\n";
  } else {
    std::cout << MOTION::Statistics::print_stats(
        "Exact Pattern Matching (windowed inputs, GMW secret-sharing → HAM/DPF)",
        run_time_stats, comm_stats);
  }
}

// ===========================================================================
// main
// ===========================================================================

int main(int argc, char* argv[]) {
  auto options = parse_program_options(argc, argv);
  if (!options.has_value()) {
    return EXIT_FAILURE;
  }

  try {
    auto comm_layer = setup_communication(*options);
    auto logger = std::make_shared<MOTION::Logger>(
        options->my_id, boost::log::trivial::severity_level::trace);
    comm_layer->set_logger(logger);
    comm_layer->start();

    // Phase 0: generate plaintext T & P (same on both parties).
    auto plain_inputs = generate_plain_inputs(*options);

    // Phase 1: window encoding BEFORE secret sharing.
    auto win_inputs   = encode_windows(*options, plain_inputs);

    MOTION::Statistics::AccumulatedRunTimeStats run_time_stats;
    MOTION::Statistics::AccumulatedCommunicationStats comm_stats;

    for (std::size_t i = 0; i < options->num_repetitions; ++i) {
      comm_layer->reset_transport_statistics();

      MOTION::TwoPartyBackend backend(*comm_layer,
                                      options->threads,
                                      options->sync_between_setup_and_online,
                                      logger);

      // Phase 2 + 3: GMW secret-sharing of windows/pattern, plus HAM/DPF
      // directly on the secret-shared window wires.
      run_circuit(*options, backend, win_inputs);

      comm_layer->sync();
      comm_stats.add(comm_layer->get_transport_statistics());
      comm_layer->reset_transport_statistics();
      run_time_stats.add(backend.get_run_time_stats());
    }

    comm_layer->shutdown();
    print_stats(*options, run_time_stats, comm_stats);

  } catch (std::runtime_error& e) {
    std::cerr << "ERROR OCCURRED: " << e.what() << "\n";
    return EXIT_FAILURE;
  }

  return EXIT_SUCCESS;
}
