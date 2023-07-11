#include "include/SubframeWorker.h"
#include "include/DCISearch.h"
#include "include/SubframeInfo.h"
#include "falcon/prof/Lifetime.h"

#include <iostream>

/* Buffers for PCH reception (not included in DL HARQ) */
const static uint32_t pch_payload_buffer_sz = 8 * 1024; // cf. srsran: srsue/hdr/mac/mac.h

SubframeWorker::SubframeWorker(uint32_t idx,
                               uint32_t max_prb,
                               PhyCommon &common,
                               DCIMetaFormats &metaFormats,
                               LTESniffer_pcap_writer *pcapwriter,
                               MCSTracking *mcs_tracking,
                               HARQ *harq,
                               int mcs_tracking_mode,
                               int harq_mode,
                               ULSchedule *ulsche,
                               int sniffer_mode) : sfb(common.nof_rx_antennas),
                                                   idx(idx),
                                                   max_prb(max_prb),
                                                   common(common),
                                                   metaFormats(metaFormats),
                                                   sf_idx(0),
                                                   sfn(0),
                                                   updateMetaFormats(false),
                                                   stats(),
                                                   pcapwriter(pcapwriter),
                                                   mcs_tracking(mcs_tracking),
                                                   harq(harq),
                                                   harq_mode(harq_mode),
                                                   mcs_tracking_mode(mcs_tracking_mode),
                                                   ulsche(ulsche),
                                                   pdschdecoder(),
                                                   puschdecoder(),
                                                   sniffer_mode(sniffer_mode),
                                                   filesink(),
                                                   est_cfo(mcs_tracking->get_est_cfo())
{
  /*Set UE-specific config for UL and DL Decoder, correct value will be set after sniffer decodes RRC Connection Setup*/
  set_ue_dl_uecfg(&ue_dl_cfg);
  set_pdsch_uecfg(&ue_dl_cfg.cfg.pdsch);
  /*Create new ue_dl*/
  falcon_ue_dl.q = new srsran_ue_dl_t;

  switch (sniffer_mode)
  {
  case DL_MODE:
    /* Config for Downlink Sniffing function*/
    srsran_ue_dl_init(falcon_ue_dl.q, sfb.sf_buffer_a, max_prb, common.nof_rx_antennas);
    /* PDSCH decoder (Downlink)*/
    pdschdecoder = new PDSCH_Decoder(idx, pcapwriter, mcs_tracking, common.getRNTIManager(), harq, mcs_tracking_mode, harq_mode, common.nof_rx_antennas);
    break;
  case UL_MODE:
    /* Config for Downlink Sniffing function*/
    srsran_ue_dl_init(falcon_ue_dl.q, sfb.sf_buffer_a, max_prb, 1); // only 1 antenna for DL in the UL Sniffer Mode
    /* PDSCH decoder (Downlink)*/
    pdschdecoder = new PDSCH_Decoder(idx,
                                     pcapwriter,
                                     mcs_tracking,
                                     common.getRNTIManager(),
                                     harq,
                                     mcs_tracking_mode,
                                     harq_mode,
                                     common.nof_rx_antennas);
    /* PUSCH decoder (Uplink)*/
    puschdecoder = new PUSCH_Decoder(enb_ul,
                                     ul_sf,
                                     ulsche,
                                     sfb.sf_buffer_b,
                                     sfb.sf_buffer_offset,
                                     ul_cfg,
                                     pcapwriter,
                                     mcs_tracking,
                                     mcs_tracking->get_debug_mode());
    /*Uplink enb init*/
    if (srsran_enb_ul_init(&enb_ul, sfb.sf_buffer_b[0], 110))
    { // 110 = max PRB
      ERROR("Error initiating ENB UL");
      return;
    }
    break;
  default:
    break;
  }
  /*Init filesink for saving IQ samples in test mode*/
  srsran_filesink_init(&filesink, "ul_sample.raw", SRSRAN_COMPLEX_FLOAT_BIN);
}

SubframeWorker::~SubframeWorker()
{
  srsran_ue_dl_free(falcon_ue_dl.q);
  delete pdschdecoder;
  pdschdecoder = nullptr;
  srsran_filesink_free(&filesink);
}

bool SubframeWorker::setCell(srsran_cell_t cell)
{
  if (srsran_ue_dl_set_cell(falcon_ue_dl.q, cell))
  {
    return false;
  }
  return true;
}

void SubframeWorker::prepare(uint32_t _sf_idx, uint32_t _sfn, bool updateMetaFormats,
                             srsran_dl_sf_cfg_t _dl_sf)
{
  this->sf_idx = _sf_idx;
  this->sfn = _sfn;
  this->updateMetaFormats = updateMetaFormats;
  dl_sf = _dl_sf;
}

uint16_t get_tti_ul_harq(uint16_t cur_tti)
{
  uint32_t temp_tti = cur_tti - 4;
  if (temp_tti >= 0)
  {
    return temp_tti;
  }
  else
  {
    temp_tti = temp_tti + 10240;
    return temp_tti;
  }
}

// int update_rv(int old_rv){
//   if (old_rv == 0){
//     return 2;
//   } else if (old_rv == 2){
//     return 3;
//   } else if (old_rv == 3){
//     return 1;
//   }
// }

void SubframeWorker::work()
{
  std::string test_string = '[' + std::to_string(idx) + ']' + '[' + std::to_string(sfn) + '-' + std::to_string(sf_idx) + ']';
  // PrintLifetime worker_lifetime(test_string + " Subframe took: ");
  uint32_t tti = sfn * 10 + sf_idx;
  ul_sf.tti = tti;
  if (updateMetaFormats)
  {
    metaFormats.update_formats();
  }

  SubframeInfo subframeInfo(falcon_ue_dl.q->cell, // contain Subframe power and DCI collection only
                            mcs_tracking_mode,
                            mcs_tracking,
                            harq_mode,
                            harq,
                            ulsche);
  DCISearch dciSearch(falcon_ue_dl,
                      metaFormats,
                      common.getRNTIManager(),
                      subframeInfo,
                      sf_idx, sfn,
                      &dl_sf, &ue_dl_cfg);
  dciSearch.setShortcutDiscovery(common.getShortcutDiscovery());

  int snr_ret = SRSRAN_SUCCESS;

  switch (sniffer_mode)
  {
  case DL_MODE:
    snr_ret = dciSearch.search();
    if (snr_ret == SRSRAN_SUCCESS)
    {                                        // only decode when SNR > 5 dB
      stats += dciSearch.getStats();         // worker-specific statistics
      common.addStats(dciSearch.getStats()); // common statistics
      run_dl_mode(subframeInfo);
    }
    else
    {
      // printf("[SIGNAL] Bad signal quality... \n");
    }
    break;
  case UL_MODE:
    dciSearch.prepareDCISearch(); // set single antenna for DL in the UL Sniffer mode
    snr_ret = dciSearch.search();
    if (snr_ret == SRSRAN_SUCCESS)
    {                                        // only decode when SNR > 5 dB
      stats += dciSearch.getStats();         // worker-specific statistics
      common.addStats(dciSearch.getStats()); // common statistics
      subframeInfo.getSubframePower().computePower(enb_ul.sf_symbols);
      run_ul_mode(subframeInfo, tti);
    }
    else
    {
      // printf("[SIGNAL] Bad signal quality... \n");
    }
    break;
  default:
    break;
  }
  /*Update CFO for ue_sync in sync thread*/
  est_cfo = falcon_ue_dl.q->chest_res.cfo;
  falcon_ue_dl.q->chest_res.cfo = 0;
  // common.consumeDCICollection(subframeInfo); //save DCI to file
  // print_nof_DCI(subframeInfo, tti);
}

void SubframeWorker::printStats()
{
  stats.print(common.getStatsFile());
}

DCIBlindSearchStats &SubframeWorker::getStats()
{
  return stats;
}

cf_t *SubframeWorker::getBuffer(uint32_t antenna_idx)
{
  return sfb.sf_buffer_a[antenna_idx];
}

void SubframeWorker::run_dl_mode(SubframeInfo &subframeInfo)
{
  pdschdecoder->init_pdsch_decoder(&falcon_ue_dl,
                                   &dl_sf,
                                   &ue_dl_cfg,
                                   &subframeInfo.getDCICollection().getDLSnifferDCI_DL(),
                                   sfn,
                                   sf_idx);
  /*Start decoding PDSCH*/
  pdschdecoder->decode_dl_mode();
}

void SubframeWorker::run_ul_mode(SubframeInfo &subframeInfo, uint32_t tti)
{
  if (!ulsche->get_config())
  {
    int sib_ret = SRSRAN_SUCCESS;
    pdschdecoder->init_pdsch_decoder(&falcon_ue_dl,
                                     &dl_sf,
                                     &ue_dl_cfg,
                                     &subframeInfo.getDCICollection().getDLSnifferDCI_DL(),
                                     sfn,
                                     sf_idx);
    sib_ret = pdschdecoder->decode_SIB();
    if (sib_ret == DL_SNIFFER_SIB2_SUCCESS)
    {
      ulsche->set_SIB2(pdschdecoder->getSIB2());
      ulsche->set_config();
    }
  }
  else
  {
    // decode uplink pusch
    if (config == false)
    {
      ul_cfg.dmrs = ulsche->get_dmrs();
      
      if (srsran_enb_ul_set_cell(&enb_ul, falcon_ue_dl.q->cell, &ul_cfg.dmrs, nullptr))
      {
        ERROR("Error set cell ENB UL");
        return;
      }
      set_config();

      // init PUSCH decoder
      // ul_cfg.hopping.hopping_enabled = true;
      ul_cfg.hopping.hop_mode = srsran_pusch_hopping_cfg_t::SRSRAN_PUSCH_HOP_MODE_INTER_SF;
      ul_cfg.hopping.hopping_offset = ulsche->sib2.rr_cfg_common.pusch_cfg_common.pusch_cfg_basic.pusch_hop_offset;
      ul_cfg.hopping.n_sb = ulsche->sib2.rr_cfg_common.pusch_cfg_common.pusch_cfg_basic.n_sb;
      ul_cfg.hopping.n_rb_ho = ulsche->sib2.rr_cfg_common.pusch_cfg_common.pusch_cfg_basic.pusch_hop_offset;

      /*RAR decode hopping config to convert dci 0 to ul grant*/
      pdschdecoder->set_hopping(ul_cfg.hopping);

      /*RACH detector config*/
      puschdecoder->set_rach_config(ulsche->get_prach_config());
      puschdecoder->set_configed();
    }
    if (puschdecoder->get_configed())
    {
      /*Decode DL messages but only TM1 as only having 1 antenna for DL*/
      pdschdecoder->init_pdsch_decoder(&falcon_ue_dl,
                                       &dl_sf,
                                       &ue_dl_cfg,
                                       &subframeInfo.getDCICollection().getDLSnifferDCI_DL(),
                                       sfn,
                                       sf_idx);

      /*Create a vector to contain RAR decoding result*/
      std::vector<DL_Sniffer_rar_result> rar_result;
      int ret = pdschdecoder->decode_ul_mode(ulsche->get_rnti(), &rar_result);

      /*Get Uplink and Downlink dci and grant lists*/
      std::vector<DCI_UL> dci_ul = subframeInfo.getDCICollection().getULSnifferDCI_UL();            // get UL DCI0 list
      std::vector<DL_Sniffer_DCI_DL> dci_dl = subframeInfo.getDCICollection().getDLSnifferDCI_DL(); // get DL DCI list
      // std::cout << "SF: " << tti/10 << "." << tti%10 << " -- Nof_DCI = " << dci_dl.size() << " / " << dci_ul.size() << std::endl;
      /*UL grant for RRC Connection Request is sent in RAR response (msg 2),
      / so convert UL grant from msg2 to general UL grant*/
      std::vector<DCI_UL> rar_dci_ul_vector;
      if (rar_result.size() > 0)
      {
        std::vector<DL_Sniffer_rar_result>::iterator rar_iter;
        for (rar_iter = rar_result.begin(); rar_iter != rar_result.end(); rar_iter++)
        {
          DCI_UL rar_dci_ul = {};
          rar_dci_ul.rnti = (*rar_iter).t_crnti;
          *rar_dci_ul.ran_ul_dci.get() = (*rar_iter).ran_dci_ul;
          *rar_dci_ul.ran_ul_grant.get() = (*rar_iter).ran_ul_grant;
          rar_dci_ul.is_rar_gant = 1;
          rar_dci_ul_vector.push_back(rar_dci_ul);
        }
      }

      /*check nof_ack for uplink pusch decoder*/
      std::vector<DCI_UL>::iterator iter_ul;
      std::vector<DL_Sniffer_DCI_DL>::iterator iter_dl;
      for (iter_ul = dci_ul.begin(); iter_ul != dci_ul.end(); iter_ul++)
      {
        for (iter_dl = dci_dl.begin(); iter_dl != dci_dl.end(); iter_dl++)
        {
          if (iter_ul->rnti == iter_dl->rnti)
          {
            if (iter_dl->ran_pdsch_grant->nof_tb == 1)
            {
              iter_ul->nof_ack = 1;
            }
            else if (iter_dl->ran_pdsch_grant->nof_tb == 2)
            {
              iter_ul->nof_ack = 2;
            }
          }
        }
      }

      /*Push current UL DCI0 to database to decode 4ms later*/
      ulsche->pushULSche(tti, dci_ul);
      // ulsche->pushULSche(tti + 1, dci_ul);
      // ulsche->pushULSche(tti - 1, dci_ul);
      // ulsche->pushULSche(tti + 2, dci_ul);
      // ulsche->pushULSche(tti - 2, dci_ul);
      /*Push current RAR grant to database to decode 4ms later*/
      ulsche->push_rar_ULSche(tti, rar_dci_ul_vector);
      // ulsche->push_rar_ULSche(tti + 1, rar_dci_ul_vector);
      // ulsche->push_rar_ULSche(tti - 1, rar_dci_ul_vector);
      puschdecoder->init_pusch_decoder(ulsche->getULSche(tti),
                                       ulsche->get_rar_ULSche(tti),
                                       ul_sf,
                                       &subframeInfo.getSubframePower());
      puschdecoder->decode();         // decode PUSCH
      puschdecoder->work_prach();     // decode PRACH
      ulsche->deleteULSche(tti);      // delete current DCI0 list and uplink grant in the database after decoding
      ulsche->delete_rar_ULSche(tti); // also for RAR grant
    }
  }
}
void SubframeWorker::setup_default_ul_cfg(srsran_ul_cfg_t &ul_cfg)
{

  ul_cfg.pusch.uci_offset.I_offset_ack = 10;
  ul_cfg.pusch.uci_offset.I_offset_cqi = 8;
  ul_cfg.pusch.uci_offset.I_offset_ri = 11;
}

void SubframeWorker::set_pdsch_uecfg(srsran_pdsch_cfg_t *pdsch_cfg)
{
  pdsch_cfg->csi_enable = true;
  pdsch_cfg->max_nof_iterations = 12;
  pdsch_cfg->meas_evm_en = false;
  pdsch_cfg->meas_time_en = false;
  pdsch_cfg->power_scale = true;
  pdsch_cfg->decoder_type = SRSRAN_MIMO_DECODER_MMSE;
  pdsch_cfg->p_a = -3;

  pdsch_cfg->p_b = 1;
  pdsch_cfg->rs_power = 0;
}

void SubframeWorker::set_ue_dl_uecfg(srsran_ue_dl_cfg_t *ue_dl_cfg)
{
  /*Set config for channel estimation*/
  srsran_chest_dl_cfg_t *chest_cfg = &ue_dl_cfg->chest_cfg;
  bzero(chest_cfg, sizeof(srsran_chest_dl_cfg_t));
  chest_cfg->filter_coef[0] = 4;
  chest_cfg->filter_coef[1] = 1;
  chest_cfg->filter_type = SRSRAN_CHEST_FILTER_GAUSS;
  chest_cfg->noise_alg = SRSRAN_NOISE_ALG_REFS;
  chest_cfg->rsrp_neighbour = false;
  chest_cfg->cfo_estimate_enable = true;
  chest_cfg->cfo_estimate_sf_mask = 1023;
  chest_cfg->sync_error_enable = false;
  chest_cfg->estimator_alg = SRSRAN_ESTIMATOR_ALG_INTERPOLATE; // Change channel estimation algorithm
                                                               // SRSRAN_ESTIMATOR_ALG_WIENER       = 2
                                                               // SRSRAN_ESTIMATOR_ALG_INTERPOLATE  = 1
                                                               // SRSRAN_ESTIMATOR_ALG_AVERAGE      = 0
  /*Set config for DCI search, can config DCI for CA cases*/
  ue_dl_cfg->cfg.dci.multiple_csi_request_enabled = false;
  ue_dl_cfg->cfg.dci.cif_enabled = false;
  ue_dl_cfg->cfg.dci.cif_present = false;
  ue_dl_cfg->cfg.dci.is_not_ue_ss = false;
  ue_dl_cfg->cfg.dci.ra_format_enabled = false;
  ue_dl_cfg->cfg.dci.srs_request_enabled = false;
}

void SubframeWorker::print_nof_DCI(SubframeInfo &subframeInfo, uint32_t tti)
{
  std::vector<DL_Sniffer_DCI_DL> dl_dci_test = subframeInfo.getDCICollection().getDLSnifferDCI_DL();
  int nof_dl_dci = dl_dci_test.size();
  std::vector<DCI_UL> dci_ul_test = subframeInfo.getDCICollection().getULSnifferDCI_UL();
  int nof_ul_dci = dci_ul_test.size();
  auto now = std::chrono::system_clock::now();
  auto micros = std::chrono::duration_cast<std::chrono::microseconds>(now.time_since_epoch());
  int nof_dci = nof_dl_dci + nof_ul_dci;
  // Convert time to string in desired format
  auto time = std::chrono::system_clock::to_time_t(now);
  std::stringstream ss;
  ss << std::put_time(std::localtime(&time), "%H:%M:%S.")
     << std::setw(6) << std::setfill('0') << micros.count() % 1000000;
  std::string time_str = ss.str();

  std::cout << time_str << "," << tti << "," << nof_dci << std::endl;
}