# Fresh Branch Verification

Date: `2026-04-13`
Worktree: `/home/vk2tlq/LTESniffer-pr-raw-io`
Binary: `/home/vk2tlq/LTESniffer-pr-raw-io/build/src/LTESniffer`

This note captures the verification runs performed from the clean PR branch itself.

## CLI surface

`-h` shows the new options:

- `-G minimum DL DCI search SNR in dB for offline replay [Default 6.0]`
- `-j treat -i as generic raw IQ and synchronize it before decoding`
- `-J raw -i/-j input is interleaved sc16 instead of cf32`
- `-Q output live raw IQ capture to cf32 file while decoding`

## Record-subframe replay

Command:

```bash
env LD_LIBRARY_PATH=/opt/install/uhd/lib \
  /home/vk2tlq/LTESniffer-pr-raw-io/build/src/LTESniffer \
  -A 1 -W 1 \
  -i /home/vk2tlq/subframe_iq_sample.bin \
  -P 2 -c 405 -p 50 -m 0 -n 200
```

Observed result:

- MIB decoded: `PCI 405 / PRB 50 / ports 2 / PHICH Resources 1`
- final stats:
  - `nof_decoded_locations=1103`
  - `nof_cce=564`
  - `nof_missed_cce=1`
  - `nof_subframes=20`
  - `nof_locations=1040`

## Direct raw `cf32` replay

Command:

```bash
env LD_LIBRARY_PATH=/opt/install/uhd/lib \
  /home/vk2tlq/LTESniffer-pr-raw-io/build/src/LTESniffer \
  -A 1 -W 4 \
  -i /home/vk2tlq/live_gold_763M_11p52M_cf32.bin \
  -j \
  -P 2 -c 405 -p 50 -G 1.0 -m 0 -n 2000
```

Observed result:

- lock point: `raw_samples=172040`
- MIB decoded: `PCI 405 / PRB 50 / ports 2 / PHICH Resources 1`
- final stats:
  - `nof_decoded_locations=72506`
  - `nof_cce=56383`
  - `nof_missed_cce=1541`
  - `nof_subframes=1954`
  - `nof_locations=104221`

## Direct raw `sc16` replay

Command:

```bash
env LD_LIBRARY_PATH=/opt/install/uhd/lib \
  /home/vk2tlq/LTESniffer-pr-raw-io/build/src/LTESniffer \
  -A 1 -W 4 \
  -i /dev/shm/iq_763M_11p52M_sc16.bin \
  -j -J \
  -P 2 -c 405 -p 50 -G 1.0 -m 0 -n 1000
```

Observed result:

- lock point: `raw_samples=81783`
- MIB decoded: `PCI 405 / PRB 50 / ports 2 / PHICH Resources 1`
- final stats:
  - `nof_decoded_locations=9613`
  - `nof_cce=11984`
  - `nof_missed_cce=24`
  - `nof_subframes=936`
  - `nof_locations=22239`

## Build notes

Two local dependency-tree fixes were needed in the generated `srsRAN` build directory on this Pi5/GCC 12 host:

- add `<array>` to `build/srsRAN-src/lib/include/srsran/srslog/bundled/fmt/core.h`
- initialize `cc_list` in `build/srsRAN-src/srsenb/src/stack/mac/nr/ue_nr.cc`

These are not branch source changes and are not intended for the pull request diff.
