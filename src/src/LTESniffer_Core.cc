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
  srsran_ue_sync_t   ue_sync;

#ifndef DISABLE_RF
  srsran_rf_t rf;             // to open RF devices
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
    char rfArgsCStr[1024];
    strncpy(rfArgsCStr, args.rf_args.c_str(), 1024);
    if (srsran_rf_open_multi(&rf, rfArgsCStr, args.rf_nof_rx_ant)) {
      fprintf(stderr, "Error opening rf\n");
      exit(-1);
    }
    /* Set receiver gain */
    if (args.rf_gain > 0) {
      srsran_rf_set_rx_gain(&rf, args.rf_gain);
    } else {
      printf("Starting AGC thread...\n");
      if (srsran_rf_start_gain_thread(&rf, false)) {
        ERROR("Error opening rf");
        exit(-1);
      }
      srsran_rf_set_rx_gain(&rf, srsran_rf_get_rx_gain(&rf));
      cell_detect_config.init_agc = srsran_rf_get_rx_gain(&rf);
    }

    /* set receiver frequency */
    if (sniffer_mode == UL_MODE && args.ul_freq != 0){
      printf("Tunning DL receiver to %.3f MHz\n", (args.rf_freq + args.file_offset_freq) / 1000000);
      if (srsran_rf_set_rx_freq(&rf, 0, args.rf_freq + args.file_offset_freq)) {
        ///ERROR("Tunning DL Freq failed\n");
      }
      /*Uplink freg*/
      printf("Tunning UL receiver to %.3f MHz\n", (double) (args.ul_freq / 1000000));
      if (srsran_rf_set_rx_freq(&rf, 1, args.ul_freq )){
        //ERROR("Tunning UL Freq failed \n");
      }
    } else if (sniffer_mode == UL_MODE && args.ul_freq == 0){
      ERROR("Uplink Frequency must be defined in the UL Sniffer Mode \n");
    } else if (sniffer_mode == DL_MODE && args.ul_freq == 0){
      printf("Tunning receiver to %.3f MHz\n", (args.rf_freq + args.file_offset_freq) / 1000000);
      srsran_rf_set_rx_freq(&rf, args.rf_nof_rx_ant, args.rf_freq + args.file_offset_freq);
    } else if (sniffer_mode == DL_MODE && args.ul_freq != 0){
        ERROR("Uplink Frequency must be 0 in the DL Sniffer Mode \n");
    }

    if (args.cell_search){
      uint32_t ntrial = 0;
      do {
        ret = rf_search_and_decode_mib(
            &rf, args.rf_nof_rx_ant, &cell_detect_config, args.force_N_id_2, &cell, &search_cell_cfo);
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
    srsran_rf_stop_rx_stream(&rf);
    // srsran_rf_flush_buffer(&rf);
    if (go_exit) {
      srsran_rf_close(&rf);
      exit(0);
    }

    /* set sampling frequency */
    int srate = srsran_sampling_freq_hz(cell.nof_prb);
    if (srate != -1) {
      printf("Setting sampling rate %.2f MHz\n", (float)srate / 1000000);
      float srate_rf = srsran_rf_set_rx_srate(&rf, (double)srate);
      if (srate_rf != srate) {
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
    if (srsran_ue_sync_init_file_multi(&ue_sync,
                                       args.nof_prb,
                                       tmp_filename,
                                       args.file_offset_time,
                                       args.file_offset_freq,
                                       args.rf_nof_rx_ant)) { //args.rf_nof_rx_ant
      ERROR("Error initiating ue_sync");
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
    if (srsran_ue_sync_init_multi_decim(&ue_sync,
                                        cell.nof_prb,
                                        cell.id == 1000,
                                        srsran_rf_recv_wrapper,
                                        args.rf_nof_rx_ant,
                                        (void*)&rf,
                                        decimate)) {
      ERROR("Error initiating ue_sync");
      exit(-1);
    }
    if (srsran_ue_sync_set_cell(&ue_sync, cell)) {
      ERROR("Error initiating ue_sync");
      exit(-1);
    }
#endif
  }

  /* set cell for every SubframeWorker*/
  if (!phy->setCell(cell)) {
    cout << "Error initiating UE downlink processing module" << endl;
    return true;
  }

  /*Get 1 worker from available list*/
  std::shared_ptr<SubframeWorker> cur_worker(phy->getAvail());
  cf_t** cur_buffer = cur_worker->getBuffers();

  /* Config mib */
  srsran_ue_mib_t ue_mib;
  if (srsran_ue_mib_init(&ue_mib, cur_buffer[0], cell.nof_prb)) {
    ERROR("Error initaiting UE MIB decoder");
    exit(-1);
  }
  if (srsran_ue_mib_set_cell(&ue_mib, cell)) {
    ERROR("Error initaiting UE MIB decoder");
    exit(-1);
  }

  // Disable CP based CFO estimation during find
  ue_sync.cfo_current_value       = search_cell_cfo / 15000;
  ue_sync.cfo_is_copied           = true;
  ue_sync.cfo_correct_enable_find = true;
  srsran_sync_set_cfo_cp_enable(&ue_sync.sfind, false, 0);
  
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
    srsran_rf_start_rx_stream(&rf, false);
  }
#endif
#ifndef DISABLE_RF
  if (args.rf_gain < 0 && args.input_file_name == "") {
    srsran_rf_info_t* rf_info = srsran_rf_get_info(&rf);
    srsran_ue_sync_start_agc(&ue_sync,
                             srsran_rf_set_rx_gain_th_wrapper_,
                             rf_info->min_rx_gain,
                             rf_info->max_rx_gain,
                             static_cast<double>(cell_detect_config.init_agc));
  }
#endif

  ue_sync.cfo_correct_enable_track = !args.disable_cfo;
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
    ret = srsran_ue_sync_zerocopy(&ue_sync, cur_worker->getBuffers(), max_num_samples);
    if (ret < 0) {
      if (args.input_file_name != ""){
        std::cout << "Finish reading from file" << std::endl;
      }
      ERROR("Error calling srsran_ue_sync_work()");
    }
    // std:: cout << "CFO = " << srsran_ue_sync_get_cfo(&ue_sync) << std::endl;
#ifdef CORRECT_SAMPLE_OFFSET
    float sample_offset =
        (float)srsran_ue_sync_get_last_sample_offset(&ue_sync) + srsran_ue_sync_get_sfo(&ue_sync) / 1000;
    srsran_ue_dl_set_sample_offset(&ue_dl, sample_offset);
#endif

    if (ret == 1){
      uint32_t sf_idx = srsran_ue_sync_get_sfidx(&ue_sync);
      switch (state) {
        case DECODE_MIB:
          if (sf_idx == 0) {
            uint8_t bch_payload[SRSRAN_BCH_PAYLOAD_LEN];
            int     sfn_offset;
            n = srsran_ue_mib_decode(&ue_mib, bch_payload, NULL, &sfn_offset);
            if (n < 0) {
              ERROR("Error decoding UE MIB");
              exit(-1);
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
        if (srsran_ue_mib_init(&ue_mib, cur_worker->getBuffers()[0], cell.nof_prb)) {
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
      cout << "Finding PSS... Peak: " << srsran_sync_get_peak_value(&ue_sync.sfind) <<
              ", FrameCnt: " << ue_sync.frame_total_cnt <<
              " State: " << ue_sync.state << endl;
    }
    sf_cnt++;

  } // main loop

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
    srsran_rf_close(&rf);
    //srsran_ue_dl_free(falcon_ue_dl.q);
    srsran_ue_sync_free(&ue_sync);
    srsran_ue_mib_free(&ue_mib);
  }
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
}

void LTESniffer_Core::stop() {
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
