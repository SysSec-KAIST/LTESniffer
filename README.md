
# LTESniffer - An Open-source LTE Downlink/Uplink Eavesdropper

**LTESniffer** is An Open-source LTE Downlink/Uplink Eavesdropper 

It first decodes the Physical Downlink Control Channel (PDCCH) to obtain the Downlink Control Informations (DCIs) and Radio Network Temporary Identifiers (RNTIs) of all active users. Using decoded DCIs and RNTIs, LTESniffer further decodes the Physical Downlink Shared Channel (PDSCH) and Physical Uplink Shared Channel (PUSCH) to retrieve uplink and downlink data traffic.

LTESniffer supports an API with three functions for security applications and research. Many LTE security research assumes
a passive sniffer that can capture privacy-related packets on the air. However, non of the current open-source sniffers satisfy their requirements as they cannot decode protocol packets in PDSCH and PUSCH. We developed a proof-of-concept security API that supports three tasks that were proposed by previous works: 1) Identity mapping, 2) IMSI collecting, and 3) Capability profiling.

Please refer to our [paper][paper] for more details.

## Guideline for setting up multiple USRP B-Series (B200/B210) for uplink sniffing mode
### Hardware Requirement
Using multiple USRPs for uplink sniffing mode requires a higher computation cost than using a single USRP X310. This is because LTESniffer needs to process multiple data streams from multiple USRPs. Therefore, it is recommended to use a powerful CPU to execute LTESniffer when using multiple USRPs.

**The following hardware is recommended**
- A single PC with Intel i7 CPU with at least 8 physical cores (in our experiments, we used i7-9700K with 8 physical cores)
- At least 16Gb RAM
- 256 Gb SSD storage
### SDR
Currently, LTESniffer only supports 2 USRP B-series (B200/B210). Both USRP B2xx(s) **MUST** be equipped with GPSDO because LTESniffer utilizes the timestamp from GPSDO to adjust uplink/downlink RF samples and achieve precise synchronization between uplink-downlink channels. Other SDRs have not been tested. Note that it is nearly impossible to operate LTESniffer in uplink sniffing mode without GPSDO.

### Installation
The Dependencies and initial setup are similar to when using a single USRP device, please refer to [main branch README][main-readme].

```bash
git clone https://github.com/SysSec-KAIST/LTESniffer.git
cd LTESniffer
git checkout LTESniffer-multi-usrp
mkdir build
cd build
cmake ../
make -j4 (use 4 threads)
```

### Make your SDR ready
After building the project the first time, please find out the serial numbers of your USRP B200/B210(s) and modify that information in the source file `src/src/LTESniffer_Core.cc`.

**Find out the serial number of USRP**
```bash
uhd_find_devices
--------------------------------------------------
-- UHD Device 0
--------------------------------------------------
Device Address:
  ->serial: 3125XXX
    name: MyB210
    product: B210
    type: b200


--------------------------------------------------
-- UHD Device 1
--------------------------------------------------
Device Address:
  ->serial: 31AEXXX
    name: MyB210
    product: B210
    type: b200

```
**Modify source file `LTESniffer_Core.cc`**

In the source file `LTESniffer_Core.cc`, please look at line `179` and `180`:
```
  std::string rf_a_string = "clock=gpsdo,num_recv_frames=512,recv_frame_size=8000,serial=3113D1B"; 
  std::string rf_b_string = "clock=gpsdo,num_recv_frames=512,recv_frame_size=8000,serial=3125CB5";
```
After that, replace the original serials with 2 serials of your B210/B200(s) and build the project again
```bash
cd ~/LTESniffer/build/
make -j4
```
**Make sure that GPSDOs in both USRP B210/B200(s) are locked**

LTESniffer requires GPSDO in both B210 to be locked before it can decode uplink signal correctly.
To achieve that, please run LTESniffer the first time, stop it (Ctrl + C) once it finishes the cell search procedure, and wait until both GPSDOs on 2 USRPs are locked. There is a led light next to the GPSDO port of USRP B210/B200 which indicates GPSDO is locked when it is lighted up (Refer to 3 steps below).

**Step 1:** Run LTESniffer first time.
```bash
sudo ./<build-dir>/src/LTESniffer -A 2 -W <number of threads> -f <DL Freq> -u <UL Freq> -C -m 1
```
After running LTESniffer the first time, because GPSDO has not been locked yet, there will be a warning notification:
```
/home/pc/LTESniffer-test/LTESniffer/build/srsRAN-src/lib/src/phy/rf/rf_uhd_imp.cc:831: Could not lock reference clock source. Sensor: gps_locked=false
```
**Step 2:** Wait until GPSDOs are locked on both USRPs (It might take 10 mins depended on GPS signal quality).

**Step3:** Once GPSDOs are locked, you can run LTESniffer to decode uplink traffic.

```bash
sudo ./<build-dir>/src/LTESniffer -A 2 -W <number of threads> -f <DL Freq> -u <UL Freq> -C -m 1
example: sudo ./src/LTESniffer -A 2 -W 4 -f 1840e6 -u 1745e6 -C -m 1
```

**Using Octoclock**

Using Octoclock with multiple USRPs seems to have a worse synchronization than using GPSDO (based on our experiments). Therefore, it is recommended to use GPSDO at this time. The synchronization of using Octoclock will be tested more and the result will be updated in the next version.

**Limitation**

When employing multiple USRP B-series for uplink sniffing mode, the success rate and DCI detection tend to be lower, reaching around 80%, in comparison to using a single USRP X310. This discrepancy can be attributed to several reasons. Firstly, despite the use of GPSDO, the synchronization between uplink and downlink channels is not as efficient as when utilizing a single USRP X310. Secondly, the USRP X310 outperforms the USRP B210/B200 in terms of RF front-end capabilities. Therefore, for the best performance, we strongly recommend using USRP X310 for uplink sniffing mode. 

### Output of LTESniffer
LTESniffer provides pcap files in the output. The pcap file can be opened by WireShark for further analysis and packet trace.
The name of downlink pcap file: ``sniffer_dl_mode.pcap``, uplink pcap file: ``sniffer_ul_mode.pcap``, and API pcap file: ``api_collector.pcap``.
The pcap files are located in the same directory ``LTESniffer`` has been executed.
To enable the WireShark to analyze the decoded packets correctly, please refer to the WireShark configuration guide [here][pcap]. There are also some examples of pcap files in the link.\
**Note:** The uplink pcap file contains both uplink and downlink messages. On the WireShark, use this filter to monitor only uplink messages: ``mac-lte.direction == 0``; or this filter to monitor only downlink messages: ``mac-lte.direction == 1``.

## Credits
We sincerely appreciate the [FALCON][falcon] and [SRS team][srsran] for making their great softwares available.
## BibTex
Please refer to our [paper][paper] for more details.

```bibtex
@inproceedings{hoang:ltesniffer,
  title = {{LTESniffer: An Open-source LTE Downlink/Uplink Eavesdropper}},
  author = {Hoang, Dinh Tuan and Park, CheolJun and Son, Mincheol and Oh, Taekkyung and Bae, Sangwook and Ahn, Junho and Oh, BeomSeok and Kim, Yongdae},
  booktitle = {16th ACM Conference on Security and Privacy in Wireless and Mobile Networks (WiSec '23)},
  year = {2023}
}
```

[falcon]: https://github.com/falkenber9/falcon
[srsran]: https://github.com/srsran/srsRAN_4G
[uhd]:    https://github.com/EttusResearch/uhd
[paper]:  https://syssec.kaist.ac.kr/pub/2023/wisec2023_tuan.pdf
[pcap]:   pcap_file_example/README.md
[app]:    https://play.google.com/store/apps/details?id=make.more.r2d2.cellular_z&hl=en&gl=US&pli=1
[watching]: https://syssec.kaist.ac.kr/pub/2022/sec22summer_bae.pdf
[main-readme]: https://github.com/SysSec-KAIST/LTESniffer/tree/main
