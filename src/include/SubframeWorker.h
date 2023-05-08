#pragma once

#include "PhyCommon.h"
#include "MetaFormats.h"
#include "DL_Sniffer_PDSCH.h"
#include "SubframeBuffer.h"
#include "falcon/phy/falcon_ue/falcon_ue_dl.h"
#include "PcapWriter.h"
#include "MCSTracking.h"
#include "ULSchedule.h"
#include "falcon/prof/Lifetime.h"
#include "UL_Sniffer_PUSCH.h"
#include "srsran/phy/io/filesink.h"
#include "Sniffer_dependency.h"

class SubframeWorker {
public:
  SubframeWorker(uint32_t idx,
                 uint32_t max_prb,
                 PhyCommon& common,
                 DCIMetaFormats& metaFormats,
                 LTESniffer_pcap_writer *pcapwriter,
                 MCSTracking *mcs_tracking,
                 HARQ *harq,
                 int mcs_tracking_mode, 
                 int harq_mode,
                 ULSchedule *ulsche, 
                 int sniffer_mode);
  ~SubframeWorker();

  bool                  setCell(srsran_cell_t cell);
  void                  prepare(uint32_t sf_idx, uint32_t sfn, bool updateMetaFormats, srsran_dl_sf_cfg_t dl_sf);
  void                  work();
  void                  printStats();
  cf_t*                 getBuffer(uint32_t antenna_idx);
  cf_t**                getBuffers() {return sfb.sf_buffer;}
  cf_t**                getBuffers_offset() {return sfb.sf_buffer_offset;}
  uint32_t              getSfidx() const {return sf_idx;}
  uint32_t              getSfn() const {return sfn;}
  void                  set_config() {config = true;}
  void                  setup_default_ul_cfg(srsran_ul_cfg_t &ul_cfg);
  void                  set_sniffer_mode(int sniffer_mode_) { sniffer_mode = sniffer_mode_;}
  void                  set_pdsch_uecfg(srsran_pdsch_cfg_t* pdsch_cfg);
  void                  set_ue_dl_uecfg(srsran_ue_dl_cfg_t* ue_dl_cfg);
  void                  run_dl_mode(SubframeInfo &subframeInfo);
  void                  run_ul_mode(SubframeInfo &subframeInfo, uint32_t tti);
  void                  set_ul_harq(UL_HARQ *ul_harq_){ ul_harq = ul_harq_;}
  void                  print_nof_DCI(SubframeInfo &subframeInfo, uint32_t tti);
  DCIBlindSearchStats&  getStats();

private:
  uint32_t              idx;
  uint32_t              max_prb;
  uint32_t              sf_idx;
  uint32_t              sfn;
  int                   sniffer_mode;
  SubframeBuffer        sfb;
  std::atomic<float>    &est_cfo;
  PhyCommon             &common;
  DCIMetaFormats        &metaFormats;
  falcon_ue_dl_t        falcon_ue_dl; //cell inside q
  srsran_dl_sf_cfg_t    dl_sf;        //cfi not
  srsran_ue_dl_cfg_t    ue_dl_cfg;    //cfg->dci cfg
  bool                  updateMetaFormats;
  bool                  collision_dw, collision_up;
  DCIBlindSearchStats   stats;
  LTESniffer_pcap_writer *pcapwriter;
  PDSCH_Decoder         *pdschdecoder;
  int                   mcs_tracking_mode;
  MCSTracking           *mcs_tracking;
  int                   harq_mode;
  HARQ                  *harq;

  //uplink
  bool                  config = false;
  bool                  has_pusch_config = false;
  ULSchedule            *ulsche;
  srsran_enb_ul_t       enb_ul = {};
  PUSCH_Decoder         *puschdecoder;
  srsran_ul_sf_cfg_t    ul_sf;
  srsran_ul_cfg_t       ul_cfg = {};
  UL_HARQ               *ul_harq;

  /*For saving IQ sample to file*/
  srsran_filesink_t     filesink;
};
