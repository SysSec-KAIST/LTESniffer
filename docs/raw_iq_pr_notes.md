# Raw IQ Replay And Capture Notes

## Scope

This branch is a clean `origin/main` derivative that keeps only the changes needed for:

- replaying generic raw IQ captures through `LTESniffer`
- writing a live raw IQ sink while decoding
- preserving compatibility with synchronized replay files produced by the `LTESniffer-record-subframe` branch

Large binary captures are intentionally not committed in this branch. See [gold_standard_manifest_2026-04-13.md](gold_standard_manifest_2026-04-13.md) for local file paths, sizes, and checksums.

## User-visible Changes

### New CLI options

- `-j`
  Treat `-i` as a generic raw IQ capture that must be synchronized before decode.
- `-J`
  Interpret raw `-i -j` input as interleaved `sc16` instead of `cf32`.
- `-Q /path/to/output.bin`
  In live RF mode, write the exact received IQ stream to a raw `cf32` file while decoding.
- `-G <dB>`
  Minimum DL DCI search SNR for offline replay. Default remains `6.0 dB` to preserve baseline behavior.

### Offline replay compatibility

- File replay now presets offline PHICH resources to `SRSRAN_PHICH_R_1`.
- This is the compatibility fix needed for files produced from the `LTESniffer-record-subframe` branch and for the validated local replay captures in this environment.

## Implementation Summary

### Raw file replay

- Added a file-backed receive callback that lets a raw IQ file behave like a live RF source.
- The raw replay path runs through `ue_sync`, waits for a stable `sf_idx 0`, and only transitions into normal decode after a valid MIB is found.
- Optional `sc16` input is converted to internal `cf_t` buffers on read.
- `-o` frequency correction is applied in the raw replay callback path.

### Live raw sink

- The RF receive wrapper can now mirror the live stream into a `cf32` file via `-Q`.
- The wrapper also tracks:
  - `overflows`
  - `late_rx`
  - `rx_errors`
  - `other_errors`
  - timestamp gap counts and magnitudes
- The summary is printed at shutdown so the capture file and decoder run can be correlated.

### Offline decode tuning

- The DL DCI SNR gate is now configurable with `-G`.
- The default stays conservative (`6.0 dB`) for reviewability and to avoid surprising baseline users.

## Review Focus

The intended review surface is:

- [ArgManager.h](../src/include/ArgManager.h)
- [ArgManager.cc](../src/src/ArgManager.cc)
- [DCISearch.h](../src/include/DCISearch.h)
- [DCISearch.cc](../src/src/DCISearch.cc)
- [Phy.h](../src/include/Phy.h)
- [Phy.cc](../src/src/Phy.cc)
- [SubframeWorker.h](../src/include/SubframeWorker.h)
- [SubframeWorker.cc](../src/src/SubframeWorker.cc)
- [LTESniffer_Core.h](../src/include/LTESniffer_Core.h)
- [LTESniffer_Core.cc](../src/src/LTESniffer_Core.cc)

## Notes For A Pull Request

- The code changes are self-contained inside `LTESniffer` and do not require the auxiliary local capture helper added in other experimental branches.
- The local verification build required the same vendored `srsRAN` GCC 12 compatibility fix as other worktrees:
  add `<array>` to `build/srsRAN-src/lib/include/srsran/srslog/bundled/fmt/core.h`.
  That is a generated dependency-tree fix and is not part of the branch source diff.
