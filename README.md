
# LTESniffer - An Open-source LTE Downlink/Uplink Eavesdropper

**LTESniffer** is An Open-source LTE Downlink/Uplink Eavesdropper 

It first decodes the Physical Downlink Control Channel (PDCCH) to obtain the Downlink Control Informations (DCIs) and Radio Network Temporary Identifiers (RNTIs) of all active users. Using decoded DCIs and RNTIs, LTESniffer further decodes the Physical Downlink Shared Channel (PDSCH) and Physical Uplink Shared Channel (PUSCH) to retrieve uplink and downlink data traffic.

LTESniffer supports an API with three functions for security applications and research. Many LTE security research assumes
a passive sniffer that can capture privacy-related packets on the air. However, non of the current open-source sniffers satisfy their requirements as they cannot decode protocol packets in PDSCH and PUSCH. We developed a proof-of-concept security API that supports three tasks that were proposed by previous works: 1) Identity mapping, 2) IMSI collecting, and 3) Capability profiling.

Please refer to our [paper][paper] for more details.

## Guidline for setting up multiple USRP B210s for uplink sniffing mode
### Hardware Requirement
Using multiple USRPs for uplink sniffing mode requires a higher computation cost than using a single USRP X310. This is because LTESniffer needs to process multiple data streams from multiple USRPs. Therefore, it is recommended to use a powerful CPU to execute LTESniffer when using multiple USRPs.

**The following hardware is recommended**
- Intel i7 CPU with at least 8 physical cores (in our experiments, we used i7-9700K with 8 physical cores)
- At least 16Gb RAM
- 256 Gb SSD storage
### SDR
Currently, LTESniffer only supports 2 USRP B210 (B200 is on testing and will be updated soon). The USRP B210 **MUST** be equipped with GPSDO, because LTESniffer requires highly precise synchronization between 2 B210, which can be achieved by using GPSDO. Other SDRs have not been tested.

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
After building the project the first time, please find out the serial number of your USRP B210s and modify that information in the source file `src/src/LTESniffer_Core.cc`.

**Find out the serial number of USRP**
```bash
uhd_find_devices
```
**Modify source file `LTESniffer_Core.cc`**

In the source file `LTESniffer_Core.cc`, please look at line `178` and `179`:
```
std::string rf_a_string = "clock=gpsdo,num_recv_frames=512,serial=XXXXXXX";
std::string rf_b_string = "clock=gpsdo,num_recv_frames=512,serial=XXXXXXX";
```
After that, replace the original serials with 2 serials of your B210 and build the project again
```bash
cd ~/LTESniffer/build/
make -j4
```
**Make sure that GPSDOs in both USRP B210 are locked**

LTESniffer requires GPSDO in both B210 to be locked before it can decode uplink signal correctly.
To obtain that, please run LTESniffer the first time, wait until it does the cell search, stop it in the middle, and wait until the GPSDOs are locked. There is a led next to the GPSDO port of B210 which indicates GPSDO is locked when it is lighted up.
```bash
sudo ./<build-dir>/src/LTESniffer -A 2 -W <number of threads> -f <DL Freq> -u <UL Freq> -C -m 1
```
Once GPSDOs are locked, you can run LTESniffer to decode uplink packets.
(note that the purpose of the first run is to make GPSDO locked, LTESniffer might not be able to decode packets correctly at that time.)
```bash
sudo ./<build-dir>/src/LTESniffer -A 2 -W <number of threads> -f <DL Freq> -u <UL Freq> -C -m 1
```

**Using Octoclock**
Using Octoclock with multiple USRPs seems to have a worse synchronization than using GPSDO (based on our experiments). Therefore, it is recommended to use GPSDO at this time. The synchronization of using Octoclock will be tested more and the result will be updated in the next version. 

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
[main-readne]: https://github.com/SysSec-KAIST/LTESniffer/tree/main
