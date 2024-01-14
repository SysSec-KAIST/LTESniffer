//#include "falcon/common/Settings.h"
#include "include/ArgManager.h"

#include "srsran/srsran.h"
#include "include/Settings.h"
#include <iostream>
#include <unistd.h>
#include <cstdio>

#define ENABLE_AGC_DEFAULT

using namespace std;

void ArgManager::defaultArgs(Args& args) {
  args.nof_subframes = DEFAULT_NOF_SUBFRAMES_TO_CAPTURE;
  args.cpu_affinity = -1;
  args.enable_ASCII_PRB_plot = true;
  args.enable_ASCII_power_plot = false;
  args.disable_cfo = false;
  args.time_offset = 0;
  args.force_N_id_2 = -1; // Pick the best
  args.input_file_name = "";
  args.dci_file_name = "";
  args.stats_file_name = "";
  args.file_offset_time = 0;
  args.file_offset_freq = 0;
  args.nof_prb = DEFAULT_NOF_PRB;
  args.file_nof_prb = DEFAULT_NOF_PRB;
  args.file_nof_ports = DEFAULT_NOF_PORTS;
  args.file_cell_id = 0;
  args.file_wrap = false;
  args.rf_args = "";
  args.rf_freq = -1.0;
  args.ul_freq = 0;
  args.rf_nof_rx_ant = DEFAULT_NOF_RX_ANT;
#ifdef ENABLE_AGC_DEFAULT
  args.rf_gain = -1.0;
#else
  args.rf_gain = 50.0;
#endif
  args.decimate = 0;
  args.nof_sniffer_thread = DEFAULT_NOF_THREAD;
  // other args
  args.dci_format_split_update_interval_ms = DEFAULT_DCI_FORMAT_SPLIT_UPDATE_INTERVAL_MS;
  args.dci_format_split_ratio = DEFAULT_DCI_FORMAT_SPLIT_RATIO;
  args.skip_secondary_meta_formats = false;
  args.enable_shortcut_discovery = true;
  args.rnti_histogram_threshold = DEFAULT_RNTI_HISTOGRAM_THRESHOLD;
  args.pcap_file = "ul_sniffer.pcap";
  args.harq_mode = 0;
  args.rnti = SRSRAN_SIRNTI;
  args.mcs_tracking_mode = 1;
  args.rf_dev = "";
  args.rf_args = "";
  args.verbose = 0;
  args.enable_cfo_ref = 1;
  args.estimator_alg = "interpolate";
  args.cell_search = false;
  args.cell_id = 0;
  args.sniffer_mode = 0;
  args.target_rnti = 0;
  args.en_debug = false;
  args.api_mode = -1; //api functions, 0: identity mapping, 1: UECapa, 2: IMSI, 3: all functions
}

void ArgManager::usage(Args& args, const std::string& prog) {
  printf("Usage: %s [aAcCDdEfghHilLnpPrRsStTvwWyYqFIuUmOoz] -f rx_frequency (in Hz) | -i input_file\n", prog.c_str());
  printf("\t-h show this help message\n");
#ifndef DISABLE_RF
  printf("\t-a RF args [Default %s]\n", args.rf_args.c_str());
#ifdef ENABLE_AGC_DEFAULT
  printf("\t-g RF fix RX gain [Default AGC]\n");
#else
  printf("\t-g Set RX gain [Default %.1f dB]\n", args.rf_gain);
#endif
#else
  printf("\t   RF is disabled.\n");
#endif
  printf("\t-i input_file [Default use RF board] (default disable)\n");
  printf("\t-D output filename for DCI [default stdout]\n");
  printf("\t-o offset frequency correction (in Hz) for input file [Default %.1f Hz]\n", args.file_offset_freq);
  printf("\t-O offset samples for input file [Default %d]\n", args.file_offset_time);
  printf("\t-P nof_ports for input file [Default %d]\n", args.file_nof_ports);
  printf("\t-c cell_id for input file [Default %d]\n", args.file_cell_id);
  printf("\t-C Enable cell search, default disable, \n");
  printf("\t-C Disable CFO correction [Default %s]\n", args.disable_cfo ? "Disabled" : "Enabled");
  printf("\t-t Add time offset [Default %d]\n", args.time_offset);
  printf("\t-y set the cpu affinity mask [Default %d]\n", args.cpu_affinity);
  printf("\t-Y set the decimate value [Default %d]\n", args.decimate);
  printf("\t-W Number of concurent threads [2..W, Default %d]\n", args.nof_sniffer_thread);
  printf("\t-s skip decoding of secondary (less frequent) DCI formats\n");
  printf("\t-S split ratio for primary/secondary DCI formats [0.0..1.0, Default %f]\n", args.dci_format_split_ratio);
  printf("\t-T interval to perform dci format split [Default %d ms]\n", args.dci_format_split_update_interval_ms);
  printf("\t-v [set srsran_verbose to debug, default none]\n");
  printf("\t-q Enable MCS table tracking algorithm (Default best: enable)\n");
  printf("\t-r Target RNTI, LTESniffer only decodes traffic of input target RNTI \n");
  printf("\t-I Specify a cell ID, need to remove -C to use this option (Default disable)\n");
  printf("\t-p Specify number of PRB of specified cell ID (-I) (Default 50)\n");
  printf("\t-f Downlink Frequency\n");
  printf("\t-u Uplink Frequency  \n");
  printf("\t-A Number of RX antennas [Default %d]\n", args.rf_nof_rx_ant);
  printf("\t-m Sniffer mode, 0 for downlink sniffing mode, 1 for uplink sniffing mode\n");
  printf("\t-z API mode, 0 for identity mapping, 1 for IMSI collecting, 2 for UECapability profiling, 3 for all\n");
  printf("\t-d Enable debug mode, print debug message to screen (Defautl disable)\n");
}

void ArgManager::parseArgs(Args& args, int argc, char **argv) {
  int opt;
  defaultArgs(args);
  while ((opt = getopt(argc, argv, "aAcCDdEfghHilLnpPrRsStTvwWyYqFIuUmOoz")) != -1) {
    switch (opt) {
      case 'a':
        args.rf_args = argv[optind];
        break;
      case 'A':
        args.rf_nof_rx_ant = static_cast<uint32_t>(strtoul(argv[optind], nullptr, 0));
        break;
      case 'g':
        args.rf_gain = strtod(argv[optind], nullptr);
        break;
      case 'L':
        args.enable_shortcut_discovery = false;
        break;
      case 'H':
        args.rnti_histogram_threshold = static_cast<uint32_t>(strtoul(argv[optind], nullptr, 0));
        break;
      case 'i':
        args.input_file_name = argv[optind];
        break;
      case 'I':
        args.cell_id = static_cast<uint32_t>(strtoul(argv[optind], nullptr, 0));
      case 'w':
        args.file_wrap = true;
        break;
      case 'D':
        args.dci_file_name = argv[optind];
        break;
      case 'd':
        args.en_debug = true;
        break;
      case 'E':
        args.stats_file_name = argv[optind];
        break;
      case 'o':
        args.file_offset_freq = strtod(argv[optind], nullptr);
        break;
      case 'O':
        args.file_offset_time = atoi(argv[optind]);
        break;
      case 'p':
        args.nof_prb = static_cast<uint32_t>(strtoul(argv[optind], nullptr, 0));
        args.file_nof_prb = args.nof_prb;
        break;
      case 'P':
        args.file_nof_ports = static_cast<uint32_t>(strtoul(argv[optind], nullptr, 0));
        break;
      case 'c':
        args.file_cell_id = static_cast<uint32_t>(strtoul(argv[optind], nullptr, 0));
        break;
      case 'l':
        args.force_N_id_2 = atoi(argv[optind]);
        break;
      case 'C':
        args.cell_search = true;
      case 'm':
        args.sniffer_mode = static_cast<uint32_t>(strtoul(argv[optind], nullptr, 0));
        break;
      case 's':
        args.skip_secondary_meta_formats = true;
        break;
      case 'S':
        args.dci_format_split_ratio = strtod(argv[optind], nullptr);
        break;
      case 't':
        args.time_offset = static_cast<uint32_t>(strtoul(argv[optind], nullptr, 0));
        break;
      case 'T':
        args.dci_format_split_update_interval_ms = static_cast<uint32_t>(strtoul(argv[optind], nullptr, 0));
        break;
      case 'r':
        args.target_rnti = atoi(argv[optind]);
        break;
      case 'R':
        args.rnti = atoi(argv[optind]); //fix here
        break;
      case 'y':
        args.cpu_affinity = atoi(argv[optind]);
        break;
      case 'Y':
        args.decimate = atoi(argv[optind]);
        break;
      case 'n':
        args.nof_subframes = static_cast<uint32_t>(strtoul(argv[optind], nullptr, 0));
        break;
      case 'W':
        args.nof_sniffer_thread = static_cast<uint32_t>(strtoul(argv[optind], nullptr, 0));
      break;
      case 'v':
        increase_srsran_verbose_level();
        args.verbose = get_srsran_verbose_level();
        break;
      case 'f':
        args.rf_freq = strtod(argv[optind], nullptr);
        break;
      case 'u':
        args.ul_freq = strtod(argv[optind], nullptr);
        break;
      case 'F':
        args.pcap_file = argv[optind];
        break;
      // case 'h':
      //   args.harq_mode = static_cast<uint32_t>(strtoul(argv[optind], nullptr, 0));
      //   break;
      case 'q':
        args.mcs_tracking_mode = static_cast<uint32_t>(strtoul(argv[optind], nullptr, 0));
        break;
      case 'z':
        args.api_mode = static_cast<uint32_t>(strtoul(argv[optind], nullptr, 0));
        break;
      case 'h':
      default:
        usage(args, argv[0]);
        exit(-1);
    }
  }

  if (args.rf_freq < 0 && args.input_file_name == "") {
    usage(args, argv[0]);
    exit(-1);
  }
}
