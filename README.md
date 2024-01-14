
# LTESniffer - An Open-source LTE Downlink/Uplink Eavesdropper

**LTESniffer** is An Open-source LTE Downlink/Uplink Eavesdropper 

It first decodes the Physical Downlink Control Channel (PDCCH) to obtain the Downlink Control Informations (DCIs) and Radio Network Temporary Identifiers (RNTIs) of all active users. Using decoded DCIs and RNTIs, LTESniffer further decodes the Physical Downlink Shared Channel (PDSCH) and Physical Uplink Shared Channel (PUSCH) to retrieve uplink and downlink data traffic.

LTESniffer supports an API with three functions for security applications and research. Many LTE security research assumes
a passive sniffer that can capture privacy-related packets on the air. However, non of the current open-source sniffers satisfy their requirements as they cannot decode protocol packets in PDSCH and PUSCH. We developed a proof-of-concept security API that supports three tasks that were proposed by previous works: 1) Identity mapping, 2) IMSI collecting, and 3) Capability profiling.

Please refer to our [paper][paper] for more details.

## Record Subframe IQ Raw Data to File
### General information

This branch enables the recording of IQ data from synchronized subframes to a file for subsequent decoding. It supports recording subframes in both Downlink and Uplink sniffing modes, which means it can record both Downlink and Uplink subframes concurrently. The recorded file is compatible with LTESniffer's offline decoding mode, making it possible to run on different PCs or locations without the need for an SDR. This functionality is particularly useful for overcoming performance issues associated with real-time decoding on lower-performance CPUs. LTESniffer can sequentially read and decode subframes from recorded files, eliminating the necessity for high-performance CPUs in real-time scenarios. Additionally, this feature simplifies the debugging process by allowing customization of LTESniffer's code and comparison of results with the same input file. For detailed instructions, please refer to the section below.

**Caution:** You should have to check your local regulations before sharing recorded files to other people.

**The following hardware is recommended**
- Single PC with Intel i7 CPU (not necessarily a high-performance PC for data recording)
- 16Gb RAM
- 500GB SSD storage (as the recorded file consumes a significant amount of storage).
### SDR
- For recording only downlink subframes in Downlink sniffing mode, USRP B200/B210/X310 are compatible and tested. Other SDRs supported by srsRAN lib might work but have not been tested.
- For recording uplink and downlink subframes concurrently, only USRP X310 is compatible. Note: using multiple USRP B200/B210s is not supported.

### Installation
The Dependencies and initial setup are similar to when using a single USRP device, please refer to [main branch README][main-readme].

```bash
git clone https://github.com/SysSec-KAIST/LTESniffer.git
cd LTESniffer
git checkout LTESniffer-record-subframe
mkdir build
cd build
cmake ../
make -j4 (use 4 threads)
```

## Usage
### Record Subframes
**Note:** This branch is designed for recording subframes to files, but it cannot be used for decoding the recorded data. To decode the recorded data, you need to use the main branch of LTESniffer, as instructed in the next section.

One main factor that can cause the recording function to fail is the Signal-to-Noise Ratio (SNR). If the SNR is too low, LTESniffer may struggle to synchronize with the recording cell or may lose synchronization during runtime. A low SNR can also degrade the quality of the recorded signal, making it challenging to successfully decode later. Thus, please check the SNR of your recording cell and find a good SNR location to run this function.

The recorded file is `subframe_iq_sample.bin`, located in the build directory.

**For recording downlink subframes in downlink sniffing mode:**
```bash
sudo ./<build-dir>/src/LTESniffer -A <number_of_antennas> -f <downlink_freq> -C -m 0 -n <number_of_subframes>
example: sudo ./src/LTESniffer -A 2 -W 4 -f 1840e6 -C -m 0 -n 5000
-A: number of antennas
-f: downlink frequency
-C: to enable cell search
-m: sniffing mode, 0 for downlink
-n: number of subframes to be recorded, note that 1 subframe lasts for 1 ms
```
**For recording DL/UL subframes in uplink sniffing mode (requires USRPX310):**
```bash
sudo ./<build-dir>/src/LTESniffer -A 2 -f <downlink_freq> -u <uplink_freq> -C -m 1 -n <number_of_subframes>
example: sudo ./src/LTESniffer -A 2 -W 4 -f 1840e6 -u 1745e6 -C -m 1 -n 5000
-A: number of antennas, it must be 2 in uplink mode
-f: downlink frequency
-u: uplink frequency
-C: to enable cell search
-m: sniffing mode, 1 for uplink
-n: number of UL/DL pair subframes to be recorded, note that 1 subframe lasts for 1 ms
```

**Important information printed on terminal**

After executing the command, essential information about the recording cell will be displayed on the terminal. Please save this information as it is necessary for correctly running offline decoding later.

```bash
 - Type:            FDD
 - PCI:             888
 - Nof ports:       2
 - CP:              Normal
 - PRB:             100
 - PHICH Length:    Normal
 - PHICH Resources: 1/6
 - SFN:             916

```

### Offline decoding using recorded files

To decode the recorded files, you need to use the offline decoding mode of the `main` branch of LTESniffer. Before running, please modify the PHICH Resources configuration in the source file `LTESniffer_Core.cc`; this information should be same as printed on terminal during the recording step above.

In the source file LTESniffer_Core.cc, please look at line `212`:
```bash
      //set up cell manually
      cell.nof_prb          = args.nof_prb;
      cell.id               = args.cell_id;
      cell.nof_ports        = 2;
      cell.cp               = SRSRAN_CP_NORM;
      cell.phich_length     = SRSRAN_PHICH_NORM;
--->  cell.phich_resources  = SRSRAN_PHICH_R_1_6;
```
There are 4 options for this, `SRSRAN_PHICH_R_1_6`, `SRSRAN_PHICH_R_1_2`, `SRSRAN_PHICH_R_1`, and `SRSRAN_PHICH_R_2`, and you should match it with the PHICH Resources printed on the terminal during the recording step. For example, if the PHICH Resources is 1/6, then the code should be corrected as SRSRAN_PHICH_R_1_6.

After that, build the project again:
```bash
cd ~/LTESniffer/build/
make -j4
```
Now you can execute the commands below to decode the recorded files. Keep in mind that all inputs **should be the same** as information printed on terminal during the recording step.

**For decoding recorded downlink subframes in downlink sniffing mode:**
```bash
sudo ./<build-dir>/src/LTESniffer -A <number_of_antenna> -W 1 -i "subframe_iq_sample.bin" -P <number_of_port> -c <cell_ID> -p <number_of_PRB> -m 0 -n <number_of_subframes> -d
example: sudo ./src/LTESniffer -A 2 -W 1 -i "subframe_iq_sample.bin" -P 2 -c 888 -p 100 -m 0 -n 5000 -d
```
**For decoding recorded DL/UL subframes in uplink sniffing mode:**
```bash
sudo ./<build-dir>/src/LTESniffer -A <number_of_antenna> -W 1 -i "subframe_iq_sample.bin" -P <number_of_port> -c <cell_ID> -p <number_of_PRB> -m 0 -n <number_of_subframes> -d
example: sudo ./src/LTESniffer -A 2 -W 1 -i "subframe_iq_sample.bin" -P 2 -c 888 -p 100 -m 1 -n 5000 -d

```

**Command options explaination**
```bash
-A: number of antennas, should be the same as you used during recording step.
-W: number of threads, set to 1 for decoding subframes one by one
-i: path to recorded file
-P: number of ports of recorded cell
-c: cell ID of recorded cell
-p: number of PRB of recorded cell
-m: sniffing mode, 1 for uplink, 0 for downlink
-n: number of recorded subframes, should be same as recorded.
-d: enable debug messages
```
The output of offline decoding mode is similar to real-time decoding mode, including pcap files and statistics on the terminal.

### Known issue
If the number of subframes is not specified in the offline decoding command (-n option), LTESniffer will not be able to determine the end of the file and will keep reading the recorded file repeatedly. As a result, the terminal output will be repeated multiple times. This issue will be fixed as soon as possible.

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
