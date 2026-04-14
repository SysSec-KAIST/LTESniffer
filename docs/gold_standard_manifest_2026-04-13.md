# Gold Standard Manifest

Date: `2026-04-13`
Host: `vk2tlq@piSDR`

This branch does not commit the raw capture binaries. The files below remain local to the host and are referenced by path and checksum for reproducibility.

## Local Files

### Live raw `cf32` gold capture

- Path: `/home/vk2tlq/live_gold_763M_11p52M_cf32.bin`
- Format: `cf32`
- Sample rate: `11.52 Msps`
- Center frequency: `763 MHz`
- Size: `922148560` bytes
- SHA256: `95cacdeb4c669bbbc7299b4fbb933f15b202100cc63e349780664081958ef70d`

### Record-subframe branch sample

- Path: `/home/vk2tlq/subframe_iq_sample.bin`
- Format: synchronized replay file emitted by `LTESniffer-record-subframe`
- Size: `17418240` bytes
- SHA256: `b33801ffee329244c0559f707b8c1864bcc24c55134eb7dcc07ebf3301d638a3`

### Robust raw `sc16` capture

- Path: `/dev/shm/iq_763M_11p52M_sc16.bin`
- Format: `sc16`
- Sample rate: `11.52 Msps`
- Center frequency: `763 MHz`
- Size: `458506240` bytes
- SHA256: `76b911f74d2f6499ff92577c6d6fc23e387e4b8a815eb30879303c6cdfb656f7`

## Why These Files Matter

- `live_gold_763M_11p52M_cf32.bin`
  Gold reference generated from the same live `LTESniffer` receive path via `-Q`.
- `subframe_iq_sample.bin`
  Confirms compatibility with the synchronized file format used by the `LTESniffer-record-subframe` branch.
- `iq_763M_11p52M_sc16.bin`
  Robust raw capture produced in the cleaned Pi5/B210 setup and replayed through `-j -J`.
