#include <stdio.h>
#include <iostream>
#include <assert.h>
#include <math.h>
#include <pthread.h>
#include <semaphore.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/time.h>
#include <unistd.h>
#include <include/SubframeBuffer.h>
#include "include/LTESniffer_Core.h"

// include C-only headers
#ifdef __cplusplus
    extern "C" {
#endif

#include "srsran/common/crash_handler.h"
#include "srsran/common/gen_mch_tables.h"
#include "srsran/phy/io/filesink.h"

#ifdef __cplusplus
}
#undef I // Fix complex.h #define I nastiness when using C++
#endif

#define ENABLE_AGC_DEFAULT
using namespace std;

cf_t  uhd_dummy_buffer0[LTESNIFFER_DUMMY_BUFFER_NOF_SAMPLE];
cf_t  uhd_dummy_buffer1[LTESNIFFER_DUMMY_BUFFER_NOF_SAMPLE];
cf_t  uhd_dummy_buffer2[LTESNIFFER_DUMMY_BUFFER_NOF_SAMPLE];
cf_t  uhd_dummy_buffer3[LTESNIFFER_DUMMY_BUFFER_NOF_SAMPLE];
cf_t* uhd_dummy_buffer[4] = {uhd_dummy_buffer0, uhd_dummy_buffer1, uhd_dummy_buffer2, uhd_dummy_buffer3}; //dummy buffer to offset data
bool  align_usrp = true;
std::atomic<bool> uhd_stop(false);// std::atomic<bool> uhd_stop(false);
std::mutex mtx_a;
std::mutex mtx_b;
std::condition_variable cv;         // to notify all uhd streamming threads to start getting samples
std::condition_variable a_fn_cv;    // notify the waiting-main thread that uhd stream a has finished
std::condition_variable b_fn_cv;    // notify the waiting-main thread that uhd stream b has finished
bool a_triggered = false;
bool b_triggered = false;
bool a_finished = false;
bool b_finished = false;
UhdStreamThread uhd_stream_thread;  //control multiple uhd threads

LTESniffer_Core::LTESniffer_Core(const Args& args):
  go_exit(false),
  args(args),
  state(DECODE_MIB),
  nof_workers(args.nof_sniffer_thread),
  mcs_tracking(args.mcs_tracking_mode, args.target_rnti, args.en_debug, args.sniffer_mode, args.api_mode, est_cfo),
  mcs_tracking_mode(args.mcs_tracking_mode),
  harq_mode(args.harq_mode),
  sniffer_mode(args.sniffer_mode),
  ulsche(args.target_rnti, &ul_harq, args.en_debug),
  api_mode(args.api_mode)
{
  srsran_filesink_init(&file_sink, "iq_sample_dl.bin", SRSRAN_COMPLEX_FLOAT_BIN);
  /*create pcap writer and name of output file*/    
  auto now = std::chrono::system_clock::now();
  std::time_t cur_time = std::chrono::system_clock::to_time_t(now);
  std::string str_cur_time(std::ctime(&cur_time));
  for(std::string::iterator it = str_cur_time.begin(); it != str_cur_time.end(); ++it) {
    if (*it == ' '){
      *it = '_';
    } else if (*it == ':'){
      *it = '.';
    } else if (*it == '\n'){
      *it = '.';
    }
  }
  std::cout << str_cur_time << std::endl;
  // std::string pcap_file_name = "ul_pcap_" + str_cur_time + "pcap";
  std::string pcap_file_name;
  std::string pcap_file_name_api = "api_collector.pcap";
  if (sniffer_mode == DL_MODE){
    pcap_file_name = "ltesniffer_dl_mode.pcap";
  } else {
    pcap_file_name = "ltesniffer_ul_mode.pcap";
  }
  pcapwriter.open(pcap_file_name, pcap_file_name_api, 0);
  /*Init HARQ*/
  harq.init_HARQ(args.harq_mode);
  /*Set multi offset in ULSchedule*/
  ulsche.set_multi_offset(args.sniffer_mode);
  /*Create PHY*/
  phy = new Phy(args.rf_nof_rx_ant,
                args.nof_sniffer_thread,
                args.dci_file_name,
                args.stats_file_name,
                args.skip_secondary_meta_formats,
                args.dci_format_split_ratio,
                args.rnti_histogram_threshold,
                &pcapwriter,
                &mcs_tracking,
                &harq,
                args.mcs_tracking_mode,
                args.harq_mode,
                &ulsche);
  phy->getCommon().setShortcutDiscovery(args.enable_shortcut_discovery);
  std::shared_ptr<DCIConsumerList> cons(new DCIConsumerList());
  if(args.dci_file_name != "") {
    cons->addConsumer(static_pointer_cast<SubframeInfoConsumer>(std::shared_ptr<DCIToFile>(new DCIToFile(phy->getCommon().getDCIFile()))));
  } 
  // if(args.enable_ASCII_PRB_plot) {
  //   cons->addConsumer(static_pointer_cast<SubframeInfoConsumer>(std::shared_ptr<DCIDrawASCII>(new DCIDrawASCII())));
  // }
  // if(args.enable_ASCII_power_plot) {
  //   cons->addConsumer(static_pointer_cast<SubframeInfoConsumer>(std::shared_ptr<PowerDrawASCII>(new PowerDrawASCII())));
  // }
  setDCIConsumer(cons);

  /* Init TA buffer to receive samples earlier than DL*/
  ta_buffer.ta_temp_buffer = static_cast<cf_t*>(srsran_vec_malloc(3*static_cast<uint32_t>(sizeof(cf_t))*static_cast<uint32_t>(SRSRAN_SF_LEN_PRB(100))));
  for (int i = 0; i<100; i++){
    ta_buffer.ta_last_sample[i] = 0;
  }
}

bool LTESniffer_Core::run(){
  cell_search_cfg_t cell_detect_config = {.max_frames_pbch    = SRSRAN_DEFAULT_MAX_FRAMES_PBCH,
                                        .max_frames_pss       = SRSRAN_DEFAULT_MAX_FRAMES_PSS,
                                        .nof_valid_pss_frames = SRSRAN_DEFAULT_NOF_VALID_PSS_FRAMES,
                                        .init_agc             = 0,
                                        .force_tdd            = false};
  srsran_cell_t      cell;
  falcon_ue_dl_t     falcon_ue_dl;
  srsran_dl_sf_cfg_t dl_sf;
  srsran_pdsch_cfg_t pdsch_cfg;
  srsran_ue_sync_t   ue_sync_a;
  srsran_ue_sync_t   ue_sync_b;

#ifndef DISABLE_RF
  srsran_rf_t rf_a;           // to open RF devices
  srsran_rf_t rf_b;
#endif
  int ret, n;                 // return
  uint8_t mch_table[10];      // unknown
  float search_cell_cfo = 0;  // freg. offset
  uint32_t sfn = 0;           // system frame number
  uint32_t skip_cnt = 0;      // number of skipped subframe
  uint32_t total_sf = 0;
  uint32_t skip_last_1s = 0;
  uint16_t nof_lost_sync = 0;
  int mcs_tracking_timer = 0;
  int update_rnti_timer = 0;
  bool start_recording = false;
  /* Set CPU affinity*/
  if (args.cpu_affinity > -1) {
    cpu_set_t cpuset;
    pthread_t thread;

    thread = pthread_self();
    for (int i = 0; i < 8; i++) {
      if (((args.cpu_affinity >> i) & 0x01) == 1) {
        printf("Setting pdsch_ue with affinity to core %d\n", i);
        CPU_SET((size_t)i, &cpuset);
      }
      if (pthread_setaffinity_np(thread, sizeof(cpu_set_t), &cpuset)) {
        ERROR("Error setting main thread affinity to %d", args.cpu_affinity);
        exit(-1);
      }
    }
  }

  /* If RF mode (not file mode)*/
#ifndef DISABLE_RF
  if (args.input_file_name == "") {
    printf("Opening RF device with %d RX antennas...\n", args.rf_nof_rx_ant);
    char rfArgsCStr_a[1024];
    char rfArgsCStr_b[1024];
    std::string rf_a_string = "clock=gpsdo,num_recv_frames=512,serial=3218D4C"; //3218D4C num_recv_frames=1024,
    std::string rf_b_string = "clock=gpsdo,num_recv_frames=512,serial=31AE210"; //3125CAD //31AE210 num_recv_frames=512,

    // std::string rf_a_string = "clock=gpsdo,type=x300,addr=192.168.40.2"; //3218D4C num_recv_frames=1024,
    // std::string rf_b_string = "clock=gpsdo,type=x300,addr=192.168.30.2"; //3125CAD //31AE210 num_recv_frames=512,

    strncpy(rfArgsCStr_a, rf_a_string.c_str(), 1024);
    strncpy(rfArgsCStr_b, rf_b_string.c_str(), 1024);

    if (srsran_rf_open_multi(&rf_a, rfArgsCStr_a, args.rf_nof_rx_ant)) { 
      fprintf(stderr, "Error opening rf_a\n");
      exit(-1);
    }
    if (srsran_rf_open_multi(&rf_b, rfArgsCStr_b, args.rf_nof_rx_ant)) {
      fprintf(stderr, "Error opening rf_b\n");
      exit(-1);
    }
    /* Set receiver gain */
    if (args.rf_gain > 0) {
      srsran_rf_set_rx_gain(&rf_a, args.rf_gain);
      srsran_rf_set_rx_gain(&rf_b, 60);
    } else {
      printf("Starting AGC thread...\n");
      if (srsran_rf_start_gain_thread(&rf_a, false)) {
        ERROR("Error opening rf_a");
        exit(-1);
      }
      if (srsran_rf_start_gain_thread(&rf_b, false)) {
        ERROR("Error opening rf_b");
        exit(-1);
      }
      srsran_rf_set_rx_gain(&rf_a, srsran_rf_get_rx_gain(&rf_a));
      srsran_rf_set_rx_gain(&rf_b, srsran_rf_get_rx_gain(&rf_b));
      cell_detect_config.init_agc = srsran_rf_get_rx_gain(&rf_a);
    }

    /* set receiver frequency */
    if (sniffer_mode == UL_MODE && args.ul_freq != 0){
      printf("Tunning DL receiver to %.3f MHz\n", (args.rf_freq + args.file_offset_freq) / 1000000);
      if (srsran_rf_set_rx_freq(&rf_a, args.rf_nof_rx_ant, args.rf_freq + args.file_offset_freq)) {
        ///ERROR("Tunning DL Freq failed\n");
      }
      /*Uplink freg*/
      printf("Tunning UL receiver to %.3f MHz\n", (double) (args.ul_freq / 1000000));
      if (srsran_rf_set_rx_freq(&rf_b, args.rf_nof_rx_ant, args.ul_freq )){
        //ERROR("Tunning UL Freq failed \n");
      }
    } else {
      ERROR("This LTESniffer branch only supports UL Sniffing with 2 USRPs \n");
    }

    if (args.cell_search){
      uint32_t ntrial = 0;
      do {
        ret = rf_search_and_decode_mib_multi_usrp(
            &rf_a, args.rf_nof_rx_ant, &cell_detect_config, args.force_N_id_2, &cell, &search_cell_cfo); //args.rf_nof_rx_ant
        if (ret < 0) {
          ERROR("Error searching for cell");
          exit(-1);
        } else if (ret == 0 && !go_exit) {
          printf("Cell not found after %d trials. Trying again (Press Ctrl+C to exit)\n", ntrial++);
        }
      } while (ret == 0 && !go_exit);
    } else{
      //set up cell manually
      cell.nof_prb          = args.nof_prb;
      cell.id               = args.cell_id;
      cell.nof_ports        = 2;
      cell.cp               = SRSRAN_CP_NORM;
      cell.phich_length     = SRSRAN_PHICH_NORM;
      cell.phich_resources  = SRSRAN_PHICH_R_1_6;
    }
    srsran_rf_stop_rx_stream(&rf_a);
    srsran_rf_stop_rx_stream(&rf_b);
    srsran_rf_flush_buffer(&rf_a);
    srsran_rf_flush_buffer(&rf_b);
    if (go_exit) {
      srsran_rf_close(&rf_a);
      srsran_rf_close(&rf_b);
      exit(0);
    }

    /* set sampling frequency */
    int srate = srsran_sampling_freq_hz(cell.nof_prb);
    if (srate != -1) {
      printf("Setting sampling rate %.2f MHz\n", (float)srate / 1000000);
      float srate_rf_a = srsran_rf_set_rx_srate(&rf_a, (double)srate);
      if (srate_rf_a != srate) {
        ERROR("Could not set sampling rate");
        exit(-1);
      }
      float srate_rf_b = srsran_rf_set_rx_srate(&rf_b, (double)srate);
      if (srate_rf_b != srate) {
        ERROR("Could not set sampling rate");
        exit(-1);
      }
    } else {
      ERROR("Invalid number of PRB %d", cell.nof_prb);
      exit(-1);
    }

    INFO("Stopping RF and flushing buffer...\r");
  }
#endif

  /* If reading from file, go straight to PDSCH decoding. Otherwise, decode MIB first */
  if (args.input_file_name != "") {
    /* preset cell configuration */
    cell.id              = args.file_cell_id;
    cell.cp              = SRSRAN_CP_NORM;
    cell.phich_length    = SRSRAN_PHICH_NORM;
    cell.phich_resources = SRSRAN_PHICH_R_1_6;
    cell.nof_ports       = args.file_nof_ports;
    cell.nof_prb         = args.nof_prb;

    char* tmp_filename = new char[args.input_file_name.length()+1];
    strncpy(tmp_filename, args.input_file_name.c_str(), args.input_file_name.length());
    tmp_filename[args.input_file_name.length()] = 0;
    if (srsran_ue_sync_init_file_multi(&ue_sync_a,
                                       args.nof_prb,
                                       tmp_filename,
                                       args.file_offset_time,
                                       args.file_offset_freq,
                                       args.rf_nof_rx_ant)) { //args.rf_nof_rx_ant
      ERROR("Error initiating ue_sync_a");
      exit(-1);
    }
    delete[] tmp_filename;
    tmp_filename = nullptr;

  } else {
#ifndef DISABLE_RF
    int decimate = 0;
    if (args.decimate) {
      if (args.decimate > 4 || args.decimate < 0) {
        printf("Invalid decimation factor, setting to 1 \n");
      } else {
        decimate = args.decimate;
      }
    }
    if (srsran_ue_sync_init_multi_usrp(&ue_sync_a,
                                        cell.nof_prb,
                                        cell.id == 1000,
                                        srsran_rf_recv_multi_usrp_wrapper,
                                        srsran_rf_recv_wrapper,
                                        2, //args.rf_nof_rx_ant
                                        (void*)&rf_a,
                                        (void*)&rf_b,
                                        decimate)) {
      ERROR("Error initiating ue_sync_a");
      exit(-1);
    }
    // if (srsran_ue_sync_init_multi_decim(&ue_sync_b,
    //                                     cell.nof_prb,
    //                                     cell.id == 1000,
    //                                     srsran_rf_recv_wrapper,
    //                                     1, //args.rf_nof_rx_ant
    //                                     (void*)&rf_b,
    //                                     decimate)) {
    //   ERROR("Error initiating ue_sync_b");
    //   exit(-1);
    // }

    if (srsran_ue_sync_set_cell(&ue_sync_a, cell)) {
      ERROR("Error initiating ue_sync_a");
      exit(-1);
    }
    // if (srsran_ue_sync_set_cell(&ue_sync_b, cell)) {
    //   ERROR("Error initiating ue_sync_b");
    //   exit(-1);
    // }
#endif
  }

  /* set cell for every SubframeWorker*/
  if (!phy->setCell(cell)) {
    cout << "Error initiating UE downlink processing module" << endl;
    return true;
  }

  /*Get 1 worker from available list*/
  std::shared_ptr<SubframeWorker> cur_worker(phy->getAvail());
  cf_t** cur_buffer_a = cur_worker->getBuffers_a();
  cf_t** cur_buffer_b = cur_worker->getBuffers_b();

  /* Config mib */
  srsran_ue_mib_t ue_mib;
  if (srsran_ue_mib_init(&ue_mib, cur_buffer_a[0], cell.nof_prb)) {
    ERROR("Error initaiting UE MIB decoder");
    exit(-1);
  }
  if (srsran_ue_mib_set_cell(&ue_mib, cell)) {
    ERROR("Error initaiting UE MIB decoder");
    exit(-1);
  }

  // Disable CP based CFO estimation during find
  ue_sync_a.cfo_current_value       = search_cell_cfo / 15000;
  ue_sync_a.cfo_is_copied           = true;
  ue_sync_a.cfo_correct_enable_find = true;
  srsran_sync_set_cfo_cp_enable(&ue_sync_a.sfind, false, 0);
  
  ZERO_OBJECT(dl_sf);
  ZERO_OBJECT(pdsch_cfg);

  pdsch_cfg.meas_evm_en = true;
  srsran_chest_dl_cfg_t chest_pdsch_cfg = {};
  chest_pdsch_cfg.cfo_estimate_enable   = args.enable_cfo_ref;
  chest_pdsch_cfg.cfo_estimate_sf_mask  = 1023;
  chest_pdsch_cfg.estimator_alg         = srsran_chest_dl_str2estimator_alg(args.estimator_alg.c_str());
  chest_pdsch_cfg.sync_error_enable     = true;

#ifndef DISABLE_RF
  if (args.input_file_name == "") {
    srsran_rf_start_rx_stream(&rf_a, false);
    srsran_rf_start_rx_stream(&rf_b, false);
  }
#endif
#ifndef DISABLE_RF
  if (args.rf_gain < 0 && args.input_file_name == "") {
    srsran_rf_info_t* rf_info_a = srsran_rf_get_info(&rf_a);
    srsran_rf_info_t* rf_info_b = srsran_rf_get_info(&rf_b);
    srsran_ue_sync_start_agc(&ue_sync_a,
                             srsran_rf_set_rx_gain_th_wrapper_,
                             rf_info_a->min_rx_gain,
                             rf_info_a->max_rx_gain,
                             static_cast<double>(cell_detect_config.init_agc));
    // srsran_rf_info_t* rf_info_b = srsran_rf_get_info(&rf_b);
    // srsran_ue_sync_start_agc(&ue_sync_b,
    //                          srsran_rf_set_rx_gain_th_wrapper_,
    //                          rf_info_b->min_rx_gain,
    //                          rf_info_b->max_rx_gain,
    //                          static_cast<double>(cell_detect_config.init_agc));
  }
#endif

  ue_sync_a.cfo_correct_enable_track = !args.disable_cfo;
  srsran_pbch_decode_reset(&ue_mib.pbch);

  // Variables for measurements
  uint32_t nframes = 0;
  float    rsrp0 = 0.0, rsrp1 = 0.0, rsrq = 0.0, snr = 0.0, enodebrate = 0.0, uerate = 0.0, procrate = 0.0,
        sinr[SRSRAN_MAX_LAYERS][SRSRAN_MAX_CODEBOOKS] = {}, sync_err[SRSRAN_MAX_PORTS][SRSRAN_MAX_PORTS] = {};
  bool decode_pdsch = false;

  uint64_t sf_cnt          = 0;
  //uint32_t sfn             = 0;
  uint32_t last_decoded_tm = 0;

  /* Length in complex samples */
  uint32_t max_num_samples = 3 * SRSRAN_SF_LEN_PRB(cell.nof_prb); 

  /* Main loop*/
  while (!go_exit && (sf_cnt < args.nof_subframes || args.nof_subframes == 0)){

    /* Set default verbose level */
    set_srsran_verbose_level(args.verbose);
    ret = srsran_ue_sync_zerocopy_multi_usrp(&ue_sync_a, cur_worker->getBuffers_a(), cur_worker->getBuffers_b(), max_num_samples);
    if (ret < 0) {
      if (args.input_file_name != ""){
        std::cout << "Finish reading from file" << std::endl;
      }
      ERROR("Error calling srsran_ue_sync_work()");
    }
    // std:: cout << "CFO = " << srsran_ue_sync_get_cfo(&ue_sync_a) << std::endl;
#ifdef CORRECT_SAMPLE_OFFSET
    float sample_offset =
        (float)srsran_ue_sync_get_last_sample_offset(&ue_sync_a) + srsran_ue_sync_get_sfo(&ue_sync_a) / 1000;
    srsran_ue_dl_set_sample_offset(&ue_dl, sample_offset);
#endif

    if (ret == 1){
      uint32_t sf_idx = srsran_ue_sync_get_sfidx(&ue_sync_a);
      // std::cout << "SF_idx: " << sf_idx << std::endl; 
      switch (state) {
        case DECODE_MIB:
          if (sf_idx == 0) {
            uint8_t bch_payload[SRSRAN_BCH_PAYLOAD_LEN];
            int     sfn_offset;
            n = srsran_ue_mib_decode(&ue_mib, bch_payload, NULL, &sfn_offset);
            if (n < 0) {
              ERROR("Error decoding UE MIB");
              exit(-1);
              std::cout << "Error decoding MIB" << std::endl;
            } else if (n == SRSRAN_UE_MIB_FOUND) {
              srsran_pbch_mib_unpack(bch_payload, &cell, &sfn);
              srsran_cell_fprint(stdout, &cell, sfn);
              printf("Decoded MIB. SFN: %d, offset: %d\n", sfn, sfn_offset);
              sfn   = (sfn + sfn_offset) % 1024;
              state = DECODE_PDSCH;

              //config RNTI Manager from Falcon Lib
              RNTIManager& rntiManager = phy->getCommon().getRNTIManager();
              // setup rnti manager
              int idx;
              // add format1A evergreens
              idx = falcon_dci_index_of_format_in_list(SRSRAN_DCI_FORMAT1A, falcon_ue_all_formats, nof_falcon_ue_all_formats);
              if(idx > -1) {
                rntiManager.addEvergreen(SRSRAN_RARNTI_START, SRSRAN_RARNTI_END, static_cast<uint32_t>(idx));
                rntiManager.addEvergreen(SRSRAN_PRNTI, SRSRAN_SIRNTI, static_cast<uint32_t>(idx));
              }
              // add format1C evergreens
              idx = falcon_dci_index_of_format_in_list(SRSRAN_DCI_FORMAT1C, falcon_ue_all_formats, nof_falcon_ue_all_formats);
              if(idx > -1) {
                rntiManager.addEvergreen(SRSRAN_RARNTI_START, SRSRAN_RARNTI_END, static_cast<uint32_t>(idx));
                rntiManager.addEvergreen(SRSRAN_PRNTI, SRSRAN_SIRNTI, static_cast<uint32_t>(idx));
              }
              // add forbidden rnti values to rnti manager
              for(uint32_t f=0; f<nof_falcon_ue_all_formats; f++) {
                  //disallow RNTI=0 for all formats
                rntiManager.addForbidden(0x0, 0x0, f);
              }
              start_recording = true;
            }
          }
          break;
        case DECODE_PDSCH:
          if ((mcs_tracking.get_nof_api_msg()%30) == 0 && api_mode > -1){
            print_api_header();
            mcs_tracking.increase_nof_api_msg();
            if (mcs_tracking.get_nof_api_msg() > 30){
              mcs_tracking.reset_nof_api_msg();
            }
          }
          uint32_t tti = sfn * 10 + sf_idx;

          /* Prepare sf_idx and sfn for worker , SF_NRM only*/
          dl_sf.tti = tti;
          dl_sf.sf_type = SRSRAN_SF_NORM;
          cur_worker->prepare(sf_idx, sfn, sf_cnt % (args.dci_format_split_update_interval_ms) == 0, dl_sf);

          /*Get next worker from avail list*/
          std:shared_ptr<SubframeWorker> next_worker;
          if(args.input_file_name == "") {
            next_worker = phy->getAvailImmediate();  //here non-blocking if reading from radio
          } else {
            next_worker = phy->getAvail();  // blocking if reading from file
          }
          if(next_worker != nullptr) {
            phy->putPending(std::move(cur_worker));
            cur_worker = std::move(next_worker);
          } else {
            // cout << "No worker available. Skipping subframe " << sfn << 
            //                                         "." << sf_idx << endl;
            skip_cnt++;
            skip_last_1s++;
          }
          break;
      }
      // if (start_recording){
      //   size_t nof_samples = SRSRAN_SF_LEN_PRB(cell.nof_prb);
      //   cf_t *temp_ptr[2];
      //   temp_ptr[0] = cur_worker->getBuffers_a()[0];
      //   temp_ptr[1] = cur_worker->getBuffers_b()[0];
      //   srsran_filesink_write_multi(&file_sink, reinterpret_cast<void**> (temp_ptr) ,nof_samples, 2);
      // }

      /*increase system frame number*/
      if (sf_idx == 9) {
        sfn++;
      }
      if (sfn == 1024){
        sfn = 0;
      }
      total_sf++;
      if ((total_sf%1000)==0 && (api_mode == -1)){
        auto now = std::chrono::system_clock::now();
        std::time_t cur_time = std::chrono::system_clock::to_time_t(now);
        std::string str_cur_time(std::ctime(&cur_time));
        std::string cur_time_second = str_cur_time.substr(11,8);
        std::cout << "[" << cur_time_second << "] Processed " << (1000 - skip_last_1s) << "/1000 subframes" << "\n";
        mcs_tracking_timer++;
        update_rnti_timer ++;
        skip_last_1s = 0;
      }
      if (update_rnti_timer == mcs_tracking.get_interval()){
        switch (sniffer_mode)
        {
        case DL_MODE:
          if (mcs_tracking_mode && args.target_rnti == 0){ mcs_tracking.update_database_dl(); }
          break;
        case UL_MODE:
          if (mcs_tracking_mode){ mcs_tracking.update_database_ul(); }
          break;
        default:
          break;
        }
        update_rnti_timer = 0;
      }
      /* Update 256tracking and harq database, delete the inactive RNTIs*/
      if (mcs_tracking_timer == 10){
        switch (sniffer_mode)
        {
        case DL_MODE:
          if (api_mode == -1) {mcs_tracking.print_database_dl();}
          if (mcs_tracking_mode && args.target_rnti == 0){ mcs_tracking.update_database_dl(); }
          if (harq_mode && args.target_rnti == 0){ harq.updateHARQDatabase(); }
          mcs_tracking_timer = 0;
          break;
        case UL_MODE:
          if (api_mode == -1) {mcs_tracking.print_database_ul();}
          if (mcs_tracking_mode){ mcs_tracking.update_database_ul(); }
          mcs_tracking_timer = 0;
          break;
        default:
          break;
        }
      }
    } else if(ret == 0){ //get buffer wrong or out of sync
      /*Change state to Decode MIB to find system frame number again*/
      if (state == DECODE_PDSCH && nof_lost_sync > 5){
        state = DECODE_MIB;
        if (srsran_ue_mib_init(&ue_mib, cur_worker->getBuffers_a()[0], cell.nof_prb)) {
          ERROR("Error initaiting UE MIB decoder");
          exit(-1);
        }
        if (srsran_ue_mib_set_cell(&ue_mib, cell)) {
          ERROR("Error initaiting UE MIB decoder");
          exit(-1);
        }
        srsran_pbch_decode_reset(&ue_mib.pbch);
        nof_lost_sync = 0;
      }
      nof_lost_sync++;
      cout << "Finding PSS... Peak: " << srsran_sync_get_peak_value(&ue_sync_a.sfind) <<
              ", FrameCnt: " << ue_sync_a.frame_total_cnt <<
              " State: " << ue_sync_a.state << endl;
    }
    sf_cnt++;

  } // main loop
  srsran_filesink_free(&file_sink);
  /* Print statistic of 256tracking*/
  if (mcs_tracking_mode){
    switch (sniffer_mode)
    {
    case DL_MODE:
      mcs_tracking.merge_all_database_dl();
      if (api_mode == -1) {mcs_tracking.print_all_database_dl(); }
      break;
    case UL_MODE:
      mcs_tracking.merge_all_database_ul();
      if (api_mode == -1) {mcs_tracking.print_all_database_ul(); }
      break;
    default:
      break;
    }
  }

  phy->joinPending();

  std::cout << "Destroyed Phy" << std::endl;
  if (args.input_file_name == ""){
    srsran_rf_close(&rf_a);
    //srsran_ue_dl_free(falcon_ue_dl.q);
    srsran_ue_sync_free(&ue_sync_a);
    srsran_ue_mib_free(&ue_mib);
  }
  uhd_stop = true;
  //common->getRNTIManager().printActiveSet();
  cout << "Skipped subframe: " << skip_cnt << " / " << sf_cnt << endl;
  //phy->getCommon().getRNTIManager().printActiveSet();
  //rnti_manager_print_active_set(falcon_ue_dl.rnti_manager);
  phy->getCommon().printStats();
  cout << "Skipped subframes: " << skip_cnt << " (" << static_cast<double>(skip_cnt) * 100 / (phy->getCommon().getStats().nof_subframes + skip_cnt) << "%)" <<  endl;
  
  /* Print statistic of 256tracking*/
  // if (mcs_tracking_mode){ mcs_tracking.print_database_ul(); }

  /* Print statistic of harq retransmission*/
  //if (harq_mode){ harq.printHARQDatabase(); }
  return EXIT_SUCCESS;
}

void LTESniffer_Core::stop() {
  uhd_stop = true;
  cout << "LTESniffer_Core: Exiting..." << endl;
  go_exit = true;
}

void LTESniffer_Core::handleSignal() {
  stop();
}

LTESniffer_Core::~LTESniffer_Core(){
  pcapwriter.close();
  // delete        harq_map;
  // harq_map    = nullptr;
  // delete        phy;
  // phy         = nullptr;
  printf("Deleted DL Sniffer core\n");
}
void LTESniffer_Core::setDCIConsumer(std::shared_ptr<SubframeInfoConsumer> consumer) {
  phy->getCommon().setDCIConsumer(consumer);
}

void LTESniffer_Core::resetDCIConsumer() {
  phy->getCommon().resetDCIConsumer();
}

RNTIManager& LTESniffer_Core::getRNTIManager(){
  return phy->getCommon().getRNTIManager();
}

void LTESniffer_Core::refreshShortcutDiscovery(bool val){
  phy->getCommon().setShortcutDiscovery(val);
}

void LTESniffer_Core::setRNTIThreshold(int val){
  if(phy){phy->getCommon().getRNTIManager().setHistogramThreshold(val);}
}

void LTESniffer_Core::print_api_header(){
  for (int i = 0; i < 90; i++){
      std::cout << "-";
  }
  std::cout << std::endl;
  std::cout << std::left << std::setw(10) <<  "SF";
  std::cout << std::left << std::setw(26) <<  "Detected Identity";
  std::cout << std::left << std::setw(17) <<  "Value";
  std::cout << std::left << std::setw(11) <<  "RNTI";  
  std::cout << std::left << std::setw(25) <<  "From Message";
  std::cout << std::endl;
  for (int i = 0; i < 90; i++){
      std::cout << "-";
  }
  std::cout << std::endl;
}

/*function to receive sample from SDR (usrp...)*/
int srsran_rf_recv_wrapper( void* h,
                            cf_t* data_[SRSRAN_MAX_PORTS], 
                            uint32_t nsamples, 
                            srsran_timestamp_t* t){
  DEBUG(" ----  Receive %d samples  ----", nsamples);
  void* ptr[SRSRAN_MAX_PORTS];
  for (int i = 0; i < SRSRAN_MAX_PORTS; i++) {
    ptr[i] = data_[i];
  }
  return srsran_rf_recv_with_time_multi((srsran_rf_t*)h, ptr, nsamples, true, NULL, NULL);
}

int extractTimeSecond(time_t secs)
{
    struct tm* timeinfo;
    timeinfo = localtime(&secs);
    int seconds = timeinfo->tm_sec;
    return seconds;
}

int srsran_rf_recv_multi_usrp_wrapper( void* rf_a,
                                       void* rf_b,
                                       cf_t* data_a[SRSRAN_MAX_PORTS],
                                       cf_t* data_b[SRSRAN_MAX_PORTS], 
                                       uint32_t nsamples, 
                                       srsran_timestamp_t* t){
  int ret = SRSRAN_ERROR;
  void* ptr_a[SRSRAN_MAX_PORTS];
  void* ptr_b[SRSRAN_MAX_PORTS];
  for (int i = 0; i < SRSRAN_MAX_PORTS; i++) {
    ptr_a[i] = data_a[i];
    ptr_b[i] = data_b[i];
  }
  
  uhd_stream_thread.prepare_stream_thread(rf_a, rf_b, nsamples, nsamples, ptr_a, ptr_b);
  // PrintLifetime uhd_lifetime("UHD took: ");
  {
    std::unique_lock<std::mutex> lock_a(mtx_a);
    std::unique_lock<std::mutex> lock_b(mtx_b);
    a_triggered = true;
    b_triggered = true;
    cv.notify_all();
  }

  //wait until 2 threads finish
  {
      std::unique_lock<std::mutex> lock_a(mtx_a);
      a_fn_cv.wait(lock_a, [] { return a_finished; });
      a_finished = false;
  }
  {
      std::unique_lock<std::mutex> lock_b(mtx_b);
      b_fn_cv.wait(lock_b, [] { return b_finished; });
      b_finished = false;
  } 

  //Check the received time of samples:
  time_t rev_secs_a       = uhd_stream_thread.get_time_secs_a();
  time_t rev_secs_b       = uhd_stream_thread.get_time_secs_b();
  double rev_frac_secs_a  = uhd_stream_thread.get_time_frac_secs_a();
  double rev_frac_secs_b  = uhd_stream_thread.get_time_frac_secs_b();
  int time_sec_a          = extractTimeSecond(rev_secs_a);
  int time_sec_b          = extractTimeSecond(rev_secs_b);
  /*If time stamp from usrp a == usrp b in second resolution, but different in fraction of second */
  if (time_sec_a == time_sec_b){
    /*calculate the time difference*/
    double diff_time = abs(rev_frac_secs_a - rev_frac_secs_b);
    /*if the time difference higher than 1 micro second*/
    if ((diff_time > 0.000001)){
      /*Convert time difference to number of samples*/
      int nof_offset_sample = diff_time * nsamples * 1000;
      /*if the number of samples higher than max buffer*/
      nof_offset_sample = (nof_offset_sample > LTESNIFFER_DUMMY_BUFFER_NOF_SAMPLE)? LTESNIFFER_DUMMY_BUFFER_NOF_SAMPLE:nof_offset_sample;
      /*prepare dummy buffer to adjust samples*/
      void* dummy_ptr[SRSRAN_MAX_PORTS];
      for (int i = 0; i < SRSRAN_MAX_PORTS; i++) {
        dummy_ptr[i] = uhd_dummy_buffer[i];
      }
      if (rev_frac_secs_a > rev_frac_secs_b){ //if usrp a is faster than usrp b
        std::cout << "[USRP] Re-align samples from USRP B, " << " -- time_a = " << rev_frac_secs_a << " -- time_b= " << rev_frac_secs_b << " -- diff = " << diff_time << " -- nof_sample = " << nof_offset_sample << std::endl;
        srsran_rf_recv_with_time_multi((srsran_rf_t*)rf_b, dummy_ptr, nof_offset_sample, true, NULL, NULL);
      }else{ // usrp b is faster than usrp a
        std::cout << "[USRP] Re-align samples from USRP A, " << " -- time_a = " << rev_frac_secs_a << " -- time_b= " << rev_frac_secs_b << " -- diff = " << diff_time << " -- nof_sample = " << nof_offset_sample << std::endl;
        srsran_rf_recv_with_time_multi((srsran_rf_t*)rf_a, dummy_ptr, nof_offset_sample, true, NULL, NULL);
      }
    }
  //if timestamp are different in many seconds, then adjust until they are equal in second
  }else if ((time_sec_a != time_sec_b) && align_usrp){ 
    int diff_time_sec = abs(time_sec_a - time_sec_b);
    void* dummy_ptr[SRSRAN_MAX_PORTS];
    for (int i = 0; i < SRSRAN_MAX_PORTS; i++) {
      dummy_ptr[i] = uhd_dummy_buffer[i];
    }
    std::cout << "[USRP] Re-align samples in second = " << diff_time_sec << std::endl;
    for (int dm_loop = 0; dm_loop < diff_time_sec*1000; dm_loop++){
      if (time_sec_a > time_sec_b){ //adjust usrp b
        srsran_rf_recv_with_time_multi((srsran_rf_t*)rf_b, dummy_ptr, nsamples, true, NULL, NULL);
      }else{
        srsran_rf_recv_with_time_multi((srsran_rf_t*)rf_a, dummy_ptr, nsamples, true, NULL, NULL);
      }
    }
    align_usrp = false;
  }

  return SRSRAN_SUCCESS;
}

UhdStreamThread::UhdStreamThread(){
  future_a = std::async(std::launch::async, [this](){
      int th_ret;
      pthread_t thread = pthread_self();
      struct sched_param params;
      params.sched_priority = 99; // Adjust the priority as needed
      th_ret = pthread_setschedparam(thread, SCHED_FIFO, &params);
      if (th_ret != 0) {
          std::cerr << "Failed to set thread priority." << std::endl;
      }      
      this->get_data_stream_a();
    });
  future_b = std::async(std::launch::async, [this](){
      int th_ret;
      pthread_t thread = pthread_self();
      struct sched_param params;
      params.sched_priority = 99; // Adjust the priority as needed
      th_ret = pthread_setschedparam(thread, SCHED_FIFO, &params);
      if (th_ret != 0) {
          std::cerr << "Failed to set thread priority." << std::endl;
      }      
      this->get_data_stream_b();
    });
}

UhdStreamThread::~UhdStreamThread(){

}

void UhdStreamThread::run(){
  // std::cout << "Getting IQ samples from USRPs " << std::endl;
  // future_a = std::async(std::launch::async, [this](){
  //     this->get_data_stream_a();
  //   });
  // future_b = std::async(std::launch::async, [this](){
  //     this->get_data_stream_b();
  //   });
  // is_running = true;
}

void UhdStreamThread::prepare_stream_thread(void* rf_a_, void* rf_b_, int nsample_a, int nsample_b, void** ptr_a_, void** ptr_b_){
  rf_a          = rf_a_;
  rf_b          = rf_b_;
  ptr_a         = ptr_a_;
  ptr_b         = ptr_b_;
  nof_sample_a  = nsample_a;
  nof_sample_b  = nsample_b;
}

int UhdStreamThread::get_data_stream_a(){
  while(!uhd_stop){
    std::unique_lock<std::mutex> lock_a(mtx_a);
    cv.wait(lock_a, [] { return a_triggered; });
    a_triggered = false;
    // std::cout << "nof_sample_a = " << nof_sample_a << std::endl;
    srsran_rf_recv_with_time_multi((srsran_rf_t*)rf_a, ptr_a, nof_sample_a, true, &secs_a, &frac_secs_a);
    
    {
      a_finished = true;
      a_fn_cv.notify_one();
    }
    lock_a.unlock();
  }
  return SRSRAN_SUCCESS;
}

int UhdStreamThread::get_data_stream_b(){
  while(!uhd_stop){
    std::unique_lock<std::mutex> lock_b(mtx_b);
    cv.wait(lock_b, [] { return b_triggered; });
    b_triggered = false;
    // std::cout << "nof_sample_b = " << nof_sample_b << std::endl;
    srsran_rf_recv_with_time_multi((srsran_rf_t*)rf_b, ptr_b, nof_sample_b, true, &secs_b, &frac_secs_b);
    
    {
      b_finished = true;
      b_fn_cv.notify_one();
    }
  }
  return SRSRAN_SUCCESS;
}

std::string UhdStreamThread::frac_sec_double_to_string(double value, int precision)
{
    std::ostringstream oss;
    oss << std::fixed << std::setprecision(precision) << value;
    std::string str = oss.str();

    // Remove the decimal point
    str.erase(std::remove(str.begin(), str.end(), '.'), str.end());

    // Add leading zeros if necessary
    int numZeros = precision - (str.length() - 1);
    str = std::string(numZeros, '0') + str;
    str = str.erase(0, 1);
    return str;
}