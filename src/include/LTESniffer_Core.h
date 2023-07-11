/*
 * Copyright (c) 2019 Robert Falkenberg.
 *
 * This file is part of FALCON 
 * (see https://github.com/falkenber9/falcon).
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * A copy of the GNU Affero General Public License can be found in
 * the LICENSE file in the top-level directory of this distribution
 * and at http://www.gnu.org/licenses/.
 */
#pragma once

#include <map>

#include "ArgManager.h"
#include "falcon/common/SignalManager.h"
#include "include/SubframeWorker.h"
#include "include/ThreadSafeQueue.h"
#include "include/WorkerThread.h"
#include "Sniffer_dependency.h"
#include "MCSTracking.h"
#include "ULSchedule.h"
#include "srsran/common/mac_pcap.h"
#include "Phy.h"
#include "PcapWriter.h"
#include "HARQ.h"
#include <ctime>
#include <iostream>
#include <boost/program_options.hpp>
#include <boost/program_options/parsers.hpp>
#include "srsue/hdr/ue.h"
#include "falcon/prof/Lifetime.h"

using namespace srsue;
namespace bpo = boost::program_options;

// include C-only headers
#ifdef __cplusplus
    extern "C" {
#endif

#include "srsran/phy/utils/debug.h"
#include "falcon/phy/falcon_ue/falcon_ue_dl.h"
#include "srsran/srsran.h"
#include "srsran/phy/rf/rf.h"
#include "srsran/phy/rf/rf_utils.h"

#ifdef __cplusplus
}
#undef I // Fix complex.h #define I nastiness when using C++
#endif
using namespace srsran;

#define UL_SNIFFER_UL_MAX_OFFSET 200
#define UL_SNIFFER_UL_OFFSET_32 32
#define UL_SNIFFER_UL_OFFSET_64 64
#define LTESNIFFER_DUMMY_BUFFER_NOF_SAMPLE (15 * 2048)

typedef struct {
  cf_t* ta_temp_buffer;
  cf_t  ta_last_sample[UL_SNIFFER_UL_MAX_OFFSET];
  int   cnt =  0;
  int   sf_sample_size;
} UL_Sniffer_ta_buffer_t;

static SRSRAN_AGC_CALLBACK(srsran_rf_set_rx_gain_th_wrapper_)
{
  srsran_rf_set_rx_gain_th((srsran_rf_t*)h, gain_db);
}

int srsran_rf_recv_wrapper( void* h,
                            cf_t* data_[SRSRAN_MAX_PORTS], 
                            uint32_t nsamples, 
                            srsran_timestamp_t* t);

int srsran_rf_recv_multi_usrp_wrapper( void* rf_a,
                                       void* rf_b,
                                       cf_t* data_a[SRSRAN_MAX_PORTS],
                                       cf_t* data_b[SRSRAN_MAX_PORTS], 
                                       uint32_t nsamples, 
                                       srsran_timestamp_t* t);

class UhdStreamThread{
public:
  UhdStreamThread();
  ~UhdStreamThread();

  void prepare_stream_thread(void* rf_a_, void* rf_b_, int nsample_a, int nsample_b, void** ptr_a_, void** ptr_b_);
  int get_data_stream_a();
  int get_data_stream_b();
  void run();
  std::string frac_sec_double_to_string(double value, int precision);  
  bool check_running(){return is_running;}
  time_t get_time_secs_a(){return secs_a;}
  time_t get_time_secs_b(){return secs_b;}
  double get_time_frac_secs_a(){return frac_secs_a;}
  double get_time_frac_secs_b(){return frac_secs_b;}
  void   set_nof_adjust_sample(int sample) { nof_adjust_sample = sample;}
  int    get_nof_adjust_sample(){ return nof_adjust_sample;}
  int    get_adjust_type(){return adjust_ab;}
  void   set_adjust_type(int type){ adjust_ab = type;}
private:
  int adjust_ab = 0; // 0: no, 1: a, 2: b
  int nof_adjust_sample = 0;
  int nof_sample_a = 0;
  int nof_sample_b = 0;
  bool is_running = false;
  void* rf_a = nullptr;
  void* rf_b = nullptr;
  void** ptr_a = nullptr;
  void** ptr_b = nullptr;
  time_t secs_a = 0;
  double frac_secs_a = 0;
  time_t secs_b = 0;
  double frac_secs_b = 0;
  int   nsamples = 0;
  std::future<void> future_a;
  std::future<void> future_b;
};

class LTESniffer_Core : public SignalHandler {
public:
  LTESniffer_Core(const Args& args);
  LTESniffer_Core(const LTESniffer_Core&) = delete; //prevent copy
  LTESniffer_Core& operator=(const LTESniffer_Core&) = delete; //prevent copy
  virtual ~LTESniffer_Core() override;
  
  RNTIManager &getRNTIManager();
  void setDCIConsumer(std::shared_ptr<SubframeInfoConsumer> consumer);
  void resetDCIConsumer();
  void refreshShortcutDiscovery(bool val);
  void setRNTIThreshold(int val);
  void print_api_header();
  bool run();
  void stop();
private:

  void handleSignal() override;

  Args                    args;
  int                     nof_workers;
  int                     sniffer_mode;     //-m
  int                     api_mode    ;     // -z
  bool                    go_exit = false;
  enum receiver_state     { DECODE_MIB, DECODE_PDSCH} state;
  std::mutex              harq_map_mutex;
  Phy                     *phy;
  LTESniffer_pcap_writer  pcapwriter;
  srsran::mac_pcap        mac_pcap;
  int                     mcs_tracking_mode;
  MCSTracking             mcs_tracking;
  ULSchedule              ulsche;
  UL_Sniffer_ta_buffer_t  ta_buffer;
  std::atomic<float>      est_cfo; //cfo from chest in subframe workers
  UL_HARQ                 ul_harq; // test UL_HARQ
  HARQ                    harq; // test HARQ function
  int                     harq_mode;
  srsran_filesink_t file_sink = {};
};
