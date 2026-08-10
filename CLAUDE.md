# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

LTESniffer is a real-time LTE downlink/uplink eavesdropper (C/C++), built on top of the FALCON library (`lib/`) and the srsRAN LTE PHY/stack (external dependency, pulled in via CMake). It decodes PDCCH to obtain DCIs/RNTIs, then uses those to decode PDSCH (downlink) and PUSCH (uplink), writing decoded MAC-LTE traffic to pcap files for analysis in Wireshark. It also exposes a security-research API (RNTI-TMSI mapping, IMSI collection, UE capability profiling).

This is research/lab tooling for passive LTE analysis with SDR hardware (USRP via UHD, BladeRF, or SoapySDR-supported devices). Only the `main` branch is checked out locally; uplink-with-2×USRP-B210 and IQ-recording features live on the `LTESniffer-multi-usrp` and `LTESniffer-record-subframe` branches respectively (not present in this checkout).

## Build

```bash
mkdir -p build && cd build
cmake ../
make -j 4
```

The binary is produced at `build/src/LTESniffer`.

Notable CMake options (set with `-D<OPTION>=<VALUE>` at configure time, see top-level `CMakeLists.txt`):
- `ENABLE_UHD` / `ENABLE_BLADERF` / `ENABLE_SOAPYSDR` — which SDR backends to link (all default ON; at least one must resolve or the build falls back to `-DDISABLE_RF`).
- `FORCE_SUBPROJECT_SRSRAN` / `FORCE_SUBPROJECT_CMNALIB` — force building srsRAN/CMNALIB from source as a CMake subproject instead of using a system install. If `find_package(SRSRAN)` / `find_package(CMNALIB)` fail, this happens automatically (srsRAN is fetched into `build/srsRAN-src` and built into `build/srsRAN-build` — this is what happened in the existing `build/` directory here).
- `CMAKE_BUILD_TYPE` — defaults to `RelWithDebInfo` if unset.
- `DISABLE_SIMD`, `USE_LTE_RATES`, `ENABLE_ASAN`, `ENABLE_MSAN`, `ENABLE_TIDY`, `BUILD_STATIC` — see `CMakeLists.txt` for details.

There is no test suite (`lib/test/CMakeLists.txt` exists but is not wired into a runnable test target in this checkout — check before assuming `ctest` works).

Required system dependencies before configuring (see `README.md` for full apt lists): UHD ≥ 4.0 built from source, srsRAN build deps (`libfftw3-dev`, `libmbedtls-dev`, `libboost-program-options-dev`, `libconfig++-dev`, `libsctp-dev`), and LTESniffer-specific deps (`libglib2.0-dev`, `libudev-dev`, `libcurl4-gnutls-dev`, `libboost-all-dev`, `qtdeclarative5-dev`, `libqt5charts5-dev`).

## Running

`LTESniffer` requires root (raw SDR access) and takes CLI flags parsed by `ArgManager` (see `src/include/ArgManager.h` / `src/src/ArgManager.cc`, defaults in `src/include/Settings.h`):

```bash
# Downlink sniffing
sudo ./build/src/LTESniffer -A 2 -W 4 -f 1840e6 -C -m 0

# Uplink sniffing (requires a second frequency)
sudo ./build/src/LTESniffer -A 2 -W 4 -f 1840e6 -u 1745e6 -C -m 1

# Security API (identity mapping / IMSI collection / UE capability profiling)
sudo ./build/src/LTESniffer -A 2 -W 4 -f 1840e6 -u 1745e6 -C -m 1 -z 3
```

Key flags: `-A` antennas, `-W` worker threads, `-f`/`-u` DL/UL frequency, `-C` enable cell search (omit and use `-I <PCI> -p <PRB>` to attach to a known cell directly), `-m` mode (0=DL, 1=UL), `-z` security API level, `-d` debug logging. USRP B210 downlink runs typically need `-a "num_recv_frames=512"` for buffering. Output pcaps (`sniffer_dl_mode.pcap`, `sniffer_ul_mode.pcap`, `api_collector.pcap`) land in the current working directory — decode with the MAC-LTE Wireshark dissector per `pcap_file_example/README.md`.

Helper scripts in `src/`: `set-cpu-governor.sh` and `performance-mode.sh` pin CPU governor for real-time decoding; `allow-realtime.sh` grants realtime scheduling capabilities; `Loop-FalconEye.sh` / `Settings-Loop-FalconEye.sh` are batch-run wrappers.

## Architecture

Two layers:

**`lib/` — FALCON library** (namespace/include prefix `falcon/`), split by concern:
- `common/` — shared settings, CSV output, signal handling (`SignalManager`/`SignalGate`), versioning.
- `phy/falcon_phch/`, `phy/falcon_ue/`, `phy/falcon_rf/` — physical-layer extensions on top of srsRAN's PHY (custom PDCCH/DCI search, DL PDSCH sniffing, UL PUSCH sniffing).
- `meas/` — netsync master/slave and broadcast master/slave machinery for multi-node measurement (not used by the core sniffer binary; leftover from FALCON's original measurement-probe use case).
- `prof/`, `util/` — profiling (`Stopwatch`, `Lifetime`) and utilities (`RNTIManager`, histograms).

**`src/` — LTESniffer application**, entry point `src/LTESniffer.cc`:
- `ArgManager` parses CLI args into an `Args` struct.
- `LTESniffer_Core` (`src/include/LTESniffer_Core.h`) is the orchestrator: owns the srsRAN `Phy`/RF handle, a pool of `SubframeWorker`s reading from a `ThreadSafeQueue` of subframes, `DCISearch`/`DCICollection` for PDCCH/DCI decoding, `DL_Sniffer_PDSCH`/`UL_Sniffer_PUSCH` for data-channel decode, `MCSTracking` and `ULSchedule` for modulation/scheduling state, `HARQ`/`UL_HARQ` for retransmission tracking, and `PcapWriter`/`srsran::mac_pcap` for output. It also owns the `RNTIManager` used by the security API.
- Threading model: `WorkerThread` + `SubframeWorker` + `ThreadSafeQueue` implement a producer/consumer pipeline — one thread reads IQ subframes from the SDR, worker threads decode them in parallel (count set by `-W`), consumers (`SubframeInfoConsumer`) drain decoded DCI/subframe info for the API and pcap output.
- The security API (`-z`) hooks into this pipeline via `setDCIConsumer`/`resetDCIConsumer` on `LTESniffer_Core` to extract identities from decoded messages without altering the core decode path.

**Dependency direction:** `src/` depends on `lib/` (FALCON) and on srsRAN (external, either system-installed or fetched as a CMake subproject into `build/srsRAN-src`); `lib/` also depends on srsRAN's PHY primitives but not on `src/`. When tracing a decode bug, follow: SDR → srsRAN RF/PHY → FALCON `phy/falcon_phch` (custom PDCCH/DCI/PDSCH/PUSCH decode) → `src/` (`SubframeWorker` → `DCISearch`/`DL_Sniffer_PDSCH`/`UL_Sniffer_PUSCH`) → `PcapWriter`/API consumers.

## Working in this repo

- This is a hardware-in-the-loop RF project: most behavior (sync, decode success rate, SNR-dependent modulation detection) cannot be verified without an actual SDR receiving a live or lab-generated LTE signal. Static analysis, build success, and code review are the only things verifiable without hardware — say so explicitly rather than claiming a decode-path change "works."
- srsRAN is a large external dependency pulled in at configure time; when it's built as a subproject, do not edit files under `build/srsRAN-src` — treat srsRAN as a fixed external API and adapt FALCON/LTESniffer code to it instead.
- License is AGPL (see `LICENSE`); FALCON portions carry their own AGPLv3 headers (Robert Falkenberg, 2019) — preserve existing copyright headers when editing files under `lib/`.
- Any change touching capture/decoding of real cellular traffic should keep the existing ethical-use framing from `README.md` in mind (lab/authorized-research use only, unencrypted-traffic-only capability).
