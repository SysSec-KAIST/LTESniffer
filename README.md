
# LTESniffer - An Open-source LTE Downlink/Uplink Eavesdropper

**LTESniffer** is An Open-source LTE Downlink/Uplink Eavesdropper 

It first decodes the Physical Downlink Control Channel (PDCCH) to obtain the Downlink Control Informations (DCIs) and Radio Network Temporary Identifiers (RNTIs) of all active users. Using decoded DCIs and RNTIs, LTESniffer further decodes the Physical Downlink Shared Channel (PDSCH) and Physical Uplink Shared Channel (PUSCH) to retrieve uplink and downlink data traffic.

LTESniffer supports an API with three functions for security applications and research. Many LTE security research assumes
a passive sniffer that can capture privacy-related packets on the air. However, non of the current open-source sniffers satisfy their requirements as they cannot decode protocol packets in PDSCH and PUSCH. We developed a proof-of-concept security API that supports three tasks that were proposed by previous works: 1) Identity mapping, 2) IMSI collecting, and 3) Capability profiling.

Please refer to our [paper][paper] for more details.

## What does LTESniffer capture?
LTESniffer captures the LTE wireless packets between the cell tower and users. It supports capturing the traffic in two directions, the downlink traffic from the cell tower to users; and the uplink traffic from nearby users to the cell tower.

LTESniffer can only obtain encrypted packets in most cases because the traffic between the cell tower and users is mostly encrypted. However, some packets are transferred in plaintext by design. For example, the following plain-text messages can be seen in the pcap files from LTESniffer:
- System Information Blocks (SIBs), which are broadcast messages containing relevant information for UEs to access the cell tower.
- Paging messages, which are broadcast messages to request UEs to establish communication with the network.
- Messages at the beginning of the connection, before the encryption is activated between UEs and the network.
## Ethical Consideration

The main purpose of LTESniffer is to support security and analysis research on the cellular network. Due to the collection of uplink-downlink user data, any use of LTESniffer must follow the local regulations on sniffing the LTE traffic. We are not responsible for any illegal purposes such as intentionally collecting user privacy-related information.

## Features
LTESniffer is implemented on top of [FALCON][falcon] with the help of [srsRAN][srsran] library. LTESniffer supports:
- Real-time decoding LTE uplink-downlink control-data channels: PDCCH, PDSCH, PUSCH
- LTE Advanced and LTE Advanced Pro, up to 256QAM in both uplink and downlink
- DCI formats: 0, 1A, 1, 1B, 1C, 2, 2A, 2B
- Transmission modes: 1, 2, 3, 4
- FDD only
- Maximum 20 MHz base station. 
- Automatically detect maximum UL/DL modulation schemes of smartphones (64QAM/256QAM on DL and 16QAM/64QAM/256QAM on UL)
- Automatically detect physical layer configuration per UE.
- LTE Security API: RNTI-TMSI mapping, IMSI collecting, UECapability Profiling.

## Hardware and Software Requirement
### OS Requirement
Currently, LTESniffer works stably on Ubuntu 18.04, other Ubuntu versions will be supported in the next release.

### Hardware Requirement
Achieving real-time decoding of LTE traffic requires a high-performance CPU with multiple physical cores. Especially when the base station has many active users during the peak hour. LTESniffer was able to achieve real-time decoding when running on an Intel i7-9700K PC to decode traffic on a base station with 150 active users.

**The following hardware is recommended**
- Intel i7 CPU with at least 8 physical cores
- At least 16Gb RAM
- 256 Gb SSD storage
### SDR
Currently, LTESniffer requires USRP X310 because it needs to synchronize with both uplink and downlink frequencies at a time. USRP X310 should be equipped with GPSDO to maintain stable synchronization. Additionally, two RX antennas are required to enable LTESniffer to decode downlink messages in transmission modes 3 and 4. 

To sniff only downlink traffic from the base station, one can operate LTESniffer with USRP B210 which is connected to PC via a USB 3.0 port. Similarly, USRB B210 should be equipped with GPSDO and two RX antennas to decode downlink messages in transmission modes 3 and 4.
## Installation
**Important note: To avoid unexpected errors, please follow the following steps on Ubuntu 18.04.**

**Dependencies**
- **Important dependency**: [UHD][uhd] library version >= 4.0 must be installed in advance (recommend building from source). The following steps can be used on Ubuntu 18.04. Refer to UHD Manual for full installation guidance. 

UHD dependencies:
```bash
sudo apt update
sudo apt-get install autoconf automake build-essential ccache cmake cpufrequtils doxygen ethtool \
g++ git inetutils-tools libboost-all-dev libncurses5 libncurses5-dev libusb-1.0-0 libusb-1.0-0-dev \
libusb-dev python3-dev python3-mako python3-numpy python3-requests python3-scipy python3-setuptools \
python3-ruamel.yaml
```
Clone and build UHD from source (make sure that the current branch is higher than 4.0)
```bash
git clone https://github.com/EttusResearch/uhd.git
cd <uhd-repo-path>/host
mkdir build
cd build
cmake ../
make -j 4
make test
sudo make install
sudo ldconfig
```
Download firmwares for USRPs:
```bash
sudo uhd_images_downloader
```
We use a [10Gb card](https://www.ettus.com/all-products/10gige-kit/) to connect USRP X310 to PC, refer to UHD Manual [[1]](https://files.ettus.com/manual/page_usrp_x3x0.html), [[2]](https://files.ettus.com/manual/page_usrp_x3x0_config.html) to configure USRP X310 and 10Gb card interface. For USRP B210, it should be connected to PC via a USB 3.0 port.

Test the connection and firmware (for USRP X310 only):
```bash
sudo sysctl -w net.core.rmem_max=33554432
sudo sysctl -w net.core.wmem_max=33554432
sudo ifconfig <10Gb card interface> mtu 9000
sudo uhd_usrp_probe
```

- srsRAN dependencies:
```bash
sudo apt-get install build-essential git cmake libfftw3-dev libmbedtls-dev libboost-program-options-dev libconfig++-dev libsctp-dev
```

- LTESniffer dependencies:
```bash
sudo apt-get install libglib2.0-dev libudev-dev libcurl4-gnutls-dev libboost-all-dev qtdeclarative5-dev libqt5charts5-dev
```

**Build LTESniffer from source:**
```bash
git clone https://github.com/SysSec-KAIST/LTESniffer.git
cd LTESniffer
mkdir build
cd build
cmake ../
make -j 4 (use 4 threads)
```
## Usage
LTESniffer has 3 main functions: 
- Sniffing LTE downlink traffic from the base station
- Sniffing LTE uplink traffic from smartphones
- Security API

After building from source, ``LTESniffer`` is located in ``<build-dir>/src/LTESniffer``

### General downlink sniffing

<p align="center">
  <img src="png/dl_mode_png.png" alt="LTESniffer Downlink Mode">
</p>

```bash
sudo ./<build-dir>/src/LTESniffer -A 2 -W <number of threads> -f <DL Freq> -C -m 0
example: sudo ./src/LTESniffer -A 2 -W 4 -f 1840e6 -C -m 0
-A: number of antennas
-W: number of threads
-f: downlink frequency
-C: turn on cell search
-m: sniffer mode, 0 for downlink sniffing and 1 for uplink sniffing
```
Note: to run ``LTESniffer`` with USRP B210 in the downlink mode, add option ``-a "num_recv_frames=512" `` to the command line.
This option extends the receiving buffer for USRP B210 to achieve better synchronization.

```bash
sudo ./<build-dir>/src/LTESniffer -A 2 -W <number of threads> -f <DL Freq> -C -m 0 -a "num_recv_frames=512"
example: sudo ./src/LTESniffer -A 2 -W 4 -f 1840e6 -C -m 0 -a "num_recv_frames=512"
```

### General uplink sniffing

<p align="center">
  <img src="png/ul_mode_png.png" alt="LTESniffer Uplink Mode">
</p>

```bash
sudo ./<build-dir>/src/LTESniffer -A 2 -W <number of threads> -f <DL Freq> -u <UL Freq> -C -m 1
example: sudo ./src/LTESniffer -A 2 -W 4 -f 1840e6 -u 1745e6 -C -m 1
-u: uplink frequency
```

### Security API

<p align="center">
  <img src="png/api_png.png" alt="LTESniffer API Mode">
</p>

```bash
sudo ./<build-dir>/src/LTESniffer -A 2 -W <number of threads> -f <DL Freq> -u <UL Freq> -C -m 1 -z 3
example: sudo ./src/LTESniffer -A 2 -W 4 -f 1840e6 -u 1745e6 -C -m 1 -z 3
-z: 3 for turnning on 3 functions of sniffer, which are identity mapping, IMSI collecting, and UECapability profiling.
    2 for UECapability profiling
    1 for IMSI collecting
    0 for identity mapping
```
### Specify a base station

LTESniffer can sniff on a specific base station by using options ``-I <Phycial Cell ID (PCI)> -p <number of Physical Resource Block (PRB)>``. In this case, LTESniffer does not do the cell search but connects directly to the specified cell.
```bash
sudo ./<build-dir>/src/LTESniffer -A 2 -W <number of threads> -f <DL Freq> -I <PCI> -p <PRB> -m 0
sudo ./<build-dir>/src/LTESniffer -A 2 -W <number of threads> -f <DL Freq> -u <UL Freq> -I <PCI> -p <PRB> -m 1
example: sudo ./src/LTESniffer -A 2 -W 4 -f 1840e6 -u 1745e6 -I 379 -p 100 -m 1
```
The debug mode can be enabled by using option ``-d``. In this case, the debug messages will be printed on the terminal.

### Output of LTESniffer

LTESniffer provides pcap files in the output. The pcap file can be opened by WireShark for further analysis and packet trace.
The name of downlink pcap file: ``sniffer_dl_mode.pcap``, uplink pcap file: ``sniffer_ul_mode.pcap``, and API pcap file: ``api_collector.pcap``.
The pcap files are located in the same directory ``LTESniffer`` has been executed.
To enable the WireShark to analyze the decoded packets correctly, please refer to the WireShark configuration guide [here][pcap]. There are also some examples of pcap files in the link.

## Application Note
### Uplink sniffing mode
When sniffing LTE uplink, LTESniffer requires USRP X310 because it needs to listen to two different frequencies at the same time, 1 for uplink and 1 for downlink. The main target of the uplink sniffing function is to decode uplink traffic from nearby smartphones. However, as LTESniffer needs to decode the downlink traffic to obtain uplink-downlink DCI messages, it also supports decoding downlink traffic at the same time. Nevertheless, the downlink sniffing function is limited to decoding messages which use transmission modes 1 and 2, since LTESniffer only has 1 antenna for downlink.
### Distance for uplink sniffing
The effective range for sniffing uplink is limited in LTESniffer due to the capability of the RF front-end of the hardware (i.e. SDR). The uplink signal power from UE is significantly weaker compared to the downlink signal because UE is a handheld device that optimizes battery usage, while the eNB uses sufficient power to cover a large area. To successfully capture the uplink traffic, LTESniffer can increase the strength of the signal power by i) being physically close to the UE, or ii) improving the signal reception capability with specialized hardware, such as a directional antenna, dedicated RF front-end, and signal amplifier.
## FAQ
**Q:** Is it possible to capture and see the phone call content using LTESniffer? \
**A:** No. LTE traffic including phone call traffic is encrypted, so you cannot use LTESniffer to know the content of phone calls of someone. Moreover, it is important to note that sniffing phone calls in the commercial network is illegal in most countries.
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