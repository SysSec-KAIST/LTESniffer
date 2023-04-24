#include "include/DCICollection.h"
#include "include/DCIPrint.h"
#include "falcon/phy/falcon_phch/falcon_dci.h"

DCICollection::DCICollection(const srsran_cell_t& cell,
                             int mcs_tracking_mode,
                             MCSTracking *mcs_tracking,
                             int harq_mode,
                             HARQ *harq,
                             ULSchedule *ulsche) :
  cell(cell),
  sfn(0),
  sf_idx(0),
  cfi(0),
  timestamp(),
  dci_dl_collection(),
  dci_ul_collection(),
  ran_dl_collection(),
  rb_map_dl(cell.nof_prb, FALCON_UNSET_RNTI),
  rb_map_ul(cell.nof_prb, FALCON_UNSET_RNTI),
  dl_collision(false),
  ul_collision(false),
  mcs_tracking_mode(mcs_tracking_mode),
  mcs_tracking(mcs_tracking),
  harq_mode(harq_mode),
  harq(harq),
  ulsche(ulsche)
{
  set_sniffer_mode(mcs_tracking->get_sniffer_mode());
  dci_dl_collection.reserve(EXPECTED_NOF_DL_DCI_PER_SUBFRAME);
  dci_ul_collection.reserve(EXPECTED_NOF_UL_DCI_PER_SUBFRAME);
  ran_dl_collection.reserve(EXPECTED_NOF_DL_DCI_PER_SUBFRAME);
}

DCICollection::~DCICollection() {

}

void DCICollection::setTimestamp(timeval timestamp) {
  this->timestamp = timestamp;
}

timeval DCICollection::getTimestamp() const {
  return timestamp;
}

void DCICollection::setSubframe(uint32_t sfn, uint32_t sf_idx, uint32_t cfi) {
  this->sfn = sfn;
  this->sf_idx = sf_idx;
  this->cfi = cfi;
}

uint32_t DCICollection::get_sfn() const {
  return sfn;
}

uint32_t DCICollection::get_sf_idx() const {
  return sf_idx;
}

uint32_t DCICollection::get_cfi() const {
  return cfi;
}

const std::vector<DCI_DL>& DCICollection::getDCI_DL() const {
  return dci_dl_collection;
}

const std::vector<DCI_UL>& DCICollection::getDCI_UL() const{
  return dci_ul_collection;
}

std::vector<DCI_UL>& DCICollection::getULSnifferDCI_UL() {
  return dci_ul_collection;
}

std::vector<DL_Sniffer_DCI_DL>& DCICollection::getDLSnifferDCI_DL(){
  return ran_dl_collection;
}

const std::vector<uint16_t>& DCICollection::getRBMapDL() const {
  return rb_map_dl;
}

const std::vector<uint16_t>& DCICollection::getRBMapUL() const {
  return rb_map_ul;
}

bool DCICollection::hasCollisionDL() const {
  return dl_collision;
}

bool DCICollection::hasCollisionUL() const {
  return ul_collision;
}

void DCICollection::addCandidate(dci_candidate_t& cand,
                                 const srsran_dci_location_t& location,
                                 uint32_t histval,
                                 srsran_dl_sf_cfg_t* sf,
                                 srsran_dci_cfg_t*   cfg)
{
  DCI_DL* dci_dl = new DCI_DL();
  DCI_UL* dci_ul = new DCI_UL();
  DL_Sniffer_DCI_DL *ran_dci_dl = new DL_Sniffer_DCI_DL;

  switch (mcs_tracking_mode)
  {
  case DL_SNIFFER_MCS_MODE_ON:
    if ((cand.rnti == SRSRAN_SIRNTI)|| 
        (cand.rnti == SRSRAN_PRNTI)||
        (SRSRAN_RNTI_ISRAR(cand.rnti))||
        (mcs_tracking_mode == false)||
        (cand.dci_msg.format == SRSRAN_DCI_FORMAT1A)) //cand.dci_msg.format <= SRSRAN_DCI_FORMAT1A
    {
      ran_dci_dl->mcs_table = DL_SNIFFER_64QAM_TABLE;
    } else {
      if (sniffer_mode == DL_MODE){
        ran_dci_dl->mcs_table = mcs_tracking->find_tracking_info_RNTI_dl(cand.rnti);
      }else{
        ran_dci_dl->mcs_table = DL_SNIFFER_UNKNOWN_TABLE;
      }
    }
    break;
  case DL_SNIFFER_MCS_MODE_OFF:
    ran_dci_dl->mcs_table = DL_SNIFFER_64QAM_TABLE;
    break;
  case DL_SNIFFER_MCS_MODE_BOTH:
    ran_dci_dl->mcs_table = DL_SNIFFER_UNKNOWN_TABLE;
    break;
  default:
    ran_dci_dl->mcs_table = DL_SNIFFER_64QAM_TABLE;
    break;
  }

  char hex_str[SRSRAN_DCI_MAX_BITS/4 + 1];
  sprint_hex(hex_str, sizeof(hex_str), cand.dci_msg.payload, cand.dci_msg.nof_bits);

  //for ran_dci_dl
  ran_dci_dl->rnti = cand.rnti;
  ran_dci_dl->format = cand.dci_msg.format;
  ran_dci_dl->nof_bits = cand.dci_msg.nof_bits;
  ran_dci_dl->hex = hex_str;
  ran_dci_dl->location = location;
  ran_dci_dl->histval = histval;
  ran_dci_dl->ran_dci_dl->rnti = cand.rnti;
  ran_dci_dl->ran_dci_dl->location = location;
  ran_dci_dl->ran_dci_dl->format = cand.dci_msg.format;

#if 0 // Verify pack/unpack hex strings
  uint8_t dci_bits[SRSRAN_DCI_MAX_BITS];
  sscan_hex(hex_str, dci_bits, msg->nof_bits);
  for(int kk = 0; kk<msg->nof_bits; kk++) {
    if(dci_bits[kk] != msg->data[kk]) {
      ERROR("Mismatch in re-unpacked hex strings");
    }
  }
#endif

  //this function needs to be replaced by a more elegant code to unpack dci
  // unpack DCI messages
  srsran_pusch_hopping_cfg_t hopping_cfg = {};
  if (ulsche->get_config()){
    //hopping_cfg.hopping_enabled = true; //review here
    hopping_cfg.hop_mode = srsran_pusch_hopping_cfg_t::SRSRAN_PUSCH_HOP_MODE_INTER_SF; // review here
    hopping_cfg.hopping_offset = ulsche->sib2.rr_cfg_common.pusch_cfg_common.pusch_cfg_basic.pusch_hop_offset;
    hopping_cfg.n_sb = ulsche->sib2.rr_cfg_common.pusch_cfg_common.pusch_cfg_basic.n_sb;
    hopping_cfg.n_rb_ho = ulsche->sib2.rr_cfg_common.pusch_cfg_common.pusch_cfg_basic.pusch_hop_offset;
  }

  ltesniffer_dci_grant_containter_t dci_grant_container{dci_dl->dl_dci_unpacked.get(),
                                                        dci_ul->ul_dci_unpacked.get(),
                                                        dci_dl->dl_grant.get(),
                                                        dci_ul->ul_grant.get(),
                                                        dci_ul->ran_ul_dci.get(), 
                                                        dci_ul->ran_ul_grant.get(),
                                                        dci_ul->ran_ul_grant_256.get(),
                                                        ran_dci_dl->ran_dci_dl.get(),
                                                        ran_dci_dl->ran_pdsch_grant.get(),
                                                        ran_dci_dl->ran_pdsch_grant_256.get()};

  srsran_dci_msg_to_trace_timestamp(&cand.dci_msg,
                                    cand.rnti,
                                    cell.nof_prb,
                                    cell.nof_ports,
                                    &dci_grant_container,
                                    ran_dci_dl->mcs_table,
                                    sf_idx,
                                    sfn,
                                    histval,
                                    location.ncce,
                                    location.L,
                                    cand.dci_msg.format,
                                    cfi,
                                    0,
                                    timestamp,
                                    histval,
                                    nullptr, 
                                    &cell, 
                                    sf, 
                                    cfg, 
                                    hopping_cfg);

  //INFO("Collecting DCI for %d, %s, cce %d, L%d\n", cand.rnti, srsran_dci_format_string(cand.dci_msg.format), location.ncce, location.L);

  // Downlink
  if (cand.dci_msg.format != SRSRAN_DCI_FORMAT0) {
    dci_dl->rnti = cand.rnti;
    dci_dl->format = cand.dci_msg.format;
    dci_dl->nof_bits = cand.dci_msg.nof_bits;
    dci_dl->hex = hex_str;
    dci_dl->location = location;
    dci_dl->histval = histval;
    /* merge total RB map for RB allocation overview */
    for(uint32_t rb_idx = 0; rb_idx < cell.nof_prb; rb_idx++) {
      if(dci_dl->dl_grant->prb_idx[0][rb_idx] == true) {
        if(rb_map_dl[rb_idx] != FALCON_UNSET_RNTI) {
          dl_collision = true;
        }
        rb_map_dl[rb_idx] = cand.rnti;
      }
      //for ran_dci_dl
    }

    if(SRSRAN_VERBOSE_ISINFO()) {
      fprintf(stdout, "%d.%d: DL [", sfn, sf_idx);
      DCIPrint::printRBVectorColored(stdout, rb_map_dl);
      fprintf(stdout, "]\n");
    }

    //q.totRBdw += dci_dl->dl_grant->nof_prb;
    //q.totBWdw += (uint32_t)(dci_dl->dl_grant->mcs[0].tbs + dci_dl->dl_grant->mcs[1].tbs);
    //if (q.totRBdw > q.q->cell.nof_prb) q.totBWdw = q.q->cell.nof_prb;

    /* get last tbs for mcs idx > 28*/
    for (int i = 0; i < SRSRAN_MAX_CODEWORDS; i++){
      if (ran_dci_dl->ran_pdsch_grant->tb[i].enabled && harq_mode){
        if (ran_dci_dl->mcs_table == DL_SNIFFER_64QAM_TABLE && ran_dci_dl->ran_pdsch_grant->tb[i].mcs_idx > 28){
          int tbs = harq->getlastTbs(ran_dci_dl->rnti, ran_dci_dl->ran_dci_dl->pid, i);
          //printf("[DCI] Detect DCI with tbs > 28 (64QAM) table, get tbs from HARQ = %d -- SF: %d-%d\n", tbs, sfn, sf_idx);
          ran_dci_dl->ran_pdsch_grant->tb[i].tbs = tbs;
          ran_dci_dl->check = true;
        } else if(ran_dci_dl->mcs_table == DL_SNIFFER_256QAM_TABLE && ran_dci_dl->ran_pdsch_grant->tb[i].mcs_idx > 27){
          int tbs = harq->getlastTbs(ran_dci_dl->rnti, ran_dci_dl->ran_dci_dl->pid, i);
          //printf("[DCI] Detect DCI with tbs > 27 (256QAM) table, get tbs from HARQ = %d -- SF: %d-%d\n", tbs, sfn, sf_idx);
          ran_dci_dl->ran_pdsch_grant->tb[i].tbs = tbs;
          ran_dci_dl->check = true;

        }
      }
    }
    for (int i = 0; i < SRSRAN_MAX_CODEWORDS; i++){
      if (ran_dci_dl->ran_pdsch_grant->tb[i].nof_bits <= 0 ){
        ran_dci_dl->ran_pdsch_grant->tb[i].enabled = false;
      }
      if (ran_dci_dl->ran_pdsch_grant_256->tb[i].nof_bits <= 0 ){
        ran_dci_dl->ran_pdsch_grant_256->tb[i].enabled = false;
      }
    }
    
    dci_dl_collection.push_back(std::move(*dci_dl));
    ran_dl_collection.push_back(std::move(*ran_dci_dl));
  }

  // Uplink
  if (cand.dci_msg.format == SRSRAN_DCI_FORMAT0) {
    dci_ul->rnti = cand.rnti;
    dci_ul->format = cand.dci_msg.format;
    dci_ul->nof_bits = cand.dci_msg.nof_bits;
    dci_ul->hex = hex_str;
    dci_ul->location = location;
    dci_ul->histval = histval;

    /* merge total RB map for RB allocation overview */
    for(uint32_t rb_idx = 0; rb_idx < dci_ul->ul_grant->L_prb; rb_idx++) {
      if(rb_map_ul[dci_ul->ul_grant->n_prb[0] + rb_idx] != FALCON_UNSET_RNTI) {
        ul_collision = true;
      }
      rb_map_ul[dci_ul->ul_grant->n_prb[0] + rb_idx] = cand.rnti;
    }

    if(SRSRAN_VERBOSE_ISINFO()) {
      fprintf(stdout, "%d.%d: UL [", sfn, sf_idx);
      DCIPrint::printRBVectorColored(stdout, rb_map_ul);
      fprintf(stdout, "]\n");
    }

    //q.totRBup += dci_ul->ul_grant->L_prb;
    //q.totBWup +=  (uint32_t) dci_ul->ul_grant->mcs.tbs;
    //if (q.totRBup > q.q->cell.nof_prb) q.totBWup = q.q->cell.nof_prb;

    dci_ul_collection.push_back(std::move(*dci_ul));
  }

  delete dci_dl;
  delete dci_ul;
  delete ran_dci_dl;
}

std::vector<uint16_t> DCICollection::applyLegacyColorMap(const std::vector<uint16_t>& RBMap) {
  std::vector<uint16_t> result(RBMap);
  for(std::vector<uint16_t>::iterator it = result.begin(); it != result.end(); ++it) {
    if(*it != FALCON_UNSET_RNTI) {
      uint16_t color = *it;
      color = (((color & 0xFF00) >> 8) | ((color & 0x00FF) << 8));
      color = (((color & 0xF0F0) >> 4) | ((color & 0x0F0F) << 4));
      color = (((color & 0xCCCC) >> 2) | ((color & 0x3333) << 2));
      color = (((color & 0xAAAA) >> 1) | ((color & 0x5555) << 1));
      color = (color >> 1) + 16000;
      *it = color;
    }
  }
  return result;
}
