#pragma once

#include <stdint.h>
#include <string>
#include "Sniffer_dependency.h"

struct Args {
  // No pointer members! Avoid shallow copies
  uint32_t    nof_subframes;
  int         cpu_affinity;
  bool        enable_ASCII_PRB_plot;
  bool        enable_ASCII_power_plot;
  bool        disable_cfo;
  uint32_t    time_offset;
  int         force_N_id_2;
  std::string input_file_name = "";
  std::string dci_file_name = "";
  std::string stats_file_name = "";
  int         file_offset_time;
  double      file_offset_freq;
  uint32_t    nof_prb;
  uint32_t    file_nof_prb;
  uint32_t    file_nof_ports;
  uint32_t    file_cell_id;
  bool        file_wrap;
  std::string rf_args;
  uint32_t    rf_nof_rx_ant;
  double      rf_freq;
  double      rf_gain;
  int         decimate;
  int         nof_sniffer_thread;
  uint32_t    cell_id = 0;
  double      ul_freq = 0;
  int         sniffer_mode = DL_MODE;
  bool        en_debug = false;

  // other config args
  uint32_t    dci_format_split_update_interval_ms;
  double      dci_format_split_ratio;
  bool        skip_secondary_meta_formats;
  bool        enable_shortcut_discovery;
  uint32_t    rnti_histogram_threshold;
  std::string pcap_file;
  int         harq_mode;
  uint16_t    rnti;
  int         mcs_tracking_mode;
  int         verbose;
  char*       rf_dev;
  //char* rf_args;
  int         enable_cfo_ref;
  std::string estimator_alg;
  bool        cell_search = false;
  uint16_t    target_rnti = 0;
  int         api_mode    = -1; //api functions, 0: identity mapping, 1: UECapa, 2: IMSI
};

class ArgManager {
public:
  static void defaultArgs(Args& args);
  static void usage(Args& args, const std::string& prog);
  static void parseArgs(Args& args, int argc, char **argv);
private:
  ArgManager() = delete;  // static only
};
