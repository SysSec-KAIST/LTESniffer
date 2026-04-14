# Gold Standard Results

Date: `2026-04-13`
Host: `vk2tlq@piSDR`

## Live capture with `-Q`

Command:

```bash
sudo env LD_LIBRARY_PATH=/opt/install/uhd/lib \
  ./LTESniffer \
  -A 1 -W 4 -f 763e6 -C -m 0 -n 10000 \
  -a "num_recv_frames=512" \
  -Q /home/vk2tlq/live_gold_763M_11p52M_cf32.bin
```

Key results:

- UHD: `4.9.0.0-0-g006d7f76`
- MIB: `PCI 405`, `PRB 50`, `ports 2`, `PHICH Resources 1`
- `nof_decoded_locations=162350`
- `nof_cce=221312`
- `nof_missed_cce=2773`
- `nof_subframes=9991`
- `nof_locations=408723`
- raw sink summary:
  - `overflows=0`
  - `late_rx=0`
  - `rx_errors=0`
  - `other_errors=0`
  - `timestamp_gap_events=0`
  - `timestamp_gap_samples_accum=0`
  - `timestamp_gap_samples_max_abs=0`
  - `file_write_failed=0`

## Offline replay of the live gold `cf32` file

Command:

```bash
env LD_LIBRARY_PATH=/opt/install/uhd/lib \
  ./LTESniffer \
  -A 1 -W 4 \
  -i /home/vk2tlq/live_gold_763M_11p52M_cf32.bin \
  -j \
  -P 2 -c 405 -p 50 -G 1.0 -m 0 -n 10000 -d
```

Key results:

- lock point: `raw_samples=172040`
- MIB: `PCI 405`, `PRB 50`, `ports 2`, `PHICH Resources 1`
- `nof_decoded_locations=159681`
- `nof_cce=219694`
- `nof_missed_cce=2780`
- `nof_subframes=9938`
- `nof_locations=405726`

Live vs replay deltas:

- `nof_decoded_locations`: `-1.64%`
- `nof_cce`: `-0.73%`
- `nof_subframes`: `-0.53%`
- `nof_locations`: `-0.73%`

Interpretation:

- direct raw replay is close to live when the file comes from the internal `-Q` sink
- this validates the raw ingest path independent of third-party capture tools

## Record-subframe compatibility

Command:

```bash
env LD_LIBRARY_PATH=/opt/install/uhd/lib \
  ./LTESniffer \
  -A 1 -W 1 \
  -i /home/vk2tlq/subframe_iq_sample.bin \
  -P 2 -c 405 -p 50 -m 0 -n 200 -d
```

Key results:

- valid MIB decode for `PCI 405 / PRB 50 / ports 2 / PHICH Resources 1`
- nonzero offline decode stats
- multiple RNTIs decoded successfully

Interpretation:

- the offline PHICH resource preset change keeps replay compatible with files produced by the `LTESniffer-record-subframe` branch

## Robust raw `sc16` replay

Capture command:

```bash
sudo env LD_LIBRARY_PATH=/opt/install/uhd/lib \
  /home/vk2tlq/LTESniffer/build/src/UhdCaptureRobust \
  --output /dev/shm/iq_763M_11p52M_sc16.bin \
  --args "type=b200,num_recv_frames=512,master_clock_rate=23.04e6" \
  --freq 763e6 \
  --rate 11.52e6 \
  --gain 50 \
  --antenna RX2 \
  --duration 10 \
  --format sc16 \
  --wirefmt sc16 \
  --metadata
```

Replay command:

```bash
env LD_LIBRARY_PATH=/opt/install/uhd/lib \
  ./LTESniffer \
  -A 1 -W 4 \
  -i /dev/shm/iq_763M_11p52M_sc16.bin \
  -j -J \
  -P 2 -c 405 -p 50 -G 1.0 -m 0 -n 9950 -d
```

Key results:

- capture: `overflows=0 timeouts=0 late=0 other_errors=0`
- replay lock: `raw_samples=81783`
- replay MIB: `PCI 405 / PRB 50 / ports 2 / PHICH Resources 1`
- `nof_decoded_locations=63229`
- `nof_cce=165327`
- `nof_missed_cce=308`
- `nof_subframes=9865`
- `nof_locations=305978`

Interpretation:

- the raw replay path works for both `cf32` and `sc16`
- the cleaned Pi5/B210 setup is stable enough to use as a baseline capture environment
