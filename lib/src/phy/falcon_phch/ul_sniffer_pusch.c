/*
 * LTE UL_Snifer version 1.0
 * 
 */

#include "falcon/phy/falcon_phch/ul_sniffer_pusch.h"
static const int tbs_table_32A[110] = 
    /* Implementation of Index 32A for uplink pusch, table Table 7.1.7.2.1-1 36.213 v15 */
    {904 , 1864 , 2792 , 3752 , 4584 , 5544 , 6456 , 7480 , 8248 , 9144 , 10296, 11064, 12216, 12960,
    14112, 14688, 15840, 16416, 17568, 18336, 19848, 20616, 21384, 22152, 22920, 24496, 25456,
    26416, 27376, 27376, 28336, 29296, 30576, 31704, 32856, 32856, 34008, 35160, 36696, 36696, 
    37888, 39232, 40576, 40576, 42368, 42368, 43816, 43816, 45352, 46888, 46888, 48936, 48936,
    51024, 51024, 52752, 52752, 52752, 55056, 55056, 57336, 57336, 59256, 59256, 59256, 61664,
    61664, 63776, 63776, 63776, 66592, 66592, 68808, 68808, 68808, 71112, 71112, 73712, 73712,
    73712, 75376, 76208, 76208, 78704, 78704, 78704, 81176, 81176, 81176, 84760, 84760, 84760,
    87936, 87936, 87936, 87936, 90816, 90816, 90816, 93800, 93800, 93800, 93800, 97896, 97896,
    97896, 97896, 101840, 101840, 101840};


int ul_sniffer_ra_ul_grant_to_grant_prb_allocation(srsran_dci_ul_t*      dci,
                                                   srsran_pusch_grant_t* grant,
                                                   uint32_t              n_rb_ho,
                                                   uint32_t              nof_prb)
{
  uint32_t n_prb_1    = 0;
  uint32_t n_rb_pusch = 0;

  srsran_ra_type2_from_riv(dci->type2_alloc.riv, &grant->L_prb, &n_prb_1, nof_prb, nof_prb);
  if (n_rb_ho % 2) {
    n_rb_ho++;
  }

  if (dci->freq_hop_fl == SRSRAN_RA_PUSCH_HOP_DISABLED || dci->freq_hop_fl == SRSRAN_RA_PUSCH_HOP_TYPE2) {
    /* For no freq hopping or type2 freq hopping, n_prb is the same
     * n_prb_tilde is calculated during resource mapping
     */
    for (uint32_t i = 0; i < 2; i++) {
      grant->n_prb[i] = n_prb_1;
    }
    if (dci->freq_hop_fl == SRSRAN_RA_PUSCH_HOP_DISABLED) {
      grant->freq_hopping = 0;
    } else {
      grant->freq_hopping = 2;
    }
    // INFO("prb1: %d, prb2: %d, L: %d", grant->n_prb[0], grant->n_prb[1], grant->L_prb);
  } else {
    /* Type1 frequency hopping as defined in 8.4.1 of 36.213
     * frequency offset between 1st and 2nd slot is fixed.
     */
    n_rb_pusch = nof_prb - n_rb_ho - (nof_prb % 2);

    // starting prb idx for slot 0 is as given by resource dci
    grant->n_prb[0] = n_prb_1;
    if (n_prb_1 < n_rb_ho / 2) {
    //   INFO("Invalid Frequency Hopping parameters. Offset: %d, n_prb_1: %d", n_rb_ho, n_prb_1);
      return SRSRAN_ERROR;
    }
    uint32_t n_prb_1_tilde = n_prb_1;

    // prb idx for slot 1
    switch (dci->freq_hop_fl) {
      case SRSRAN_RA_PUSCH_HOP_QUART:
        grant->n_prb[1] = (n_rb_pusch / 4 + n_prb_1_tilde) % n_rb_pusch;
        break;
      case SRSRAN_RA_PUSCH_HOP_QUART_NEG:
        if (n_prb_1 < n_rb_pusch / 4) {
          grant->n_prb[1] = (n_rb_pusch + n_prb_1_tilde - n_rb_pusch / 4);
        } else {
          grant->n_prb[1] = (n_prb_1_tilde - n_rb_pusch / 4);
        }
        break;
      case SRSRAN_RA_PUSCH_HOP_HALF:
        grant->n_prb[1] = (n_rb_pusch / 2 + n_prb_1_tilde) % n_rb_pusch;
        break;
      default:
        break;
    }
    // INFO("n_rb_pusch: %d, prb1: %d, prb2: %d, L: %d", n_rb_pusch, grant->n_prb[0], grant->n_prb[1], grant->L_prb);
    grant->freq_hopping = 1;
  }

  if (grant->n_prb[0] + grant->L_prb <= nof_prb && grant->n_prb[1] + grant->L_prb <= nof_prb) {
    return SRSRAN_SUCCESS;
  } else {
    return SRSRAN_ERROR;
  }
}


/*implemetation of modulation and coding scheme convertion in table 8.6.1-3 on 36.213*/
int ul_fill_ra_mcs_256(srsran_ra_tb_t* tb, srsran_ra_tb_t* last_tb, uint32_t L_prb, bool cqi_request)
{
  if (tb->mcs_idx <= 28) {
    /* Table 8.6.1-3 on 36.213 */
    if (tb->mcs_idx < 6) {
      tb->mod = SRSRAN_MOD_QPSK;
      tb->tbs = srsran_ra_tbs_from_idx((tb->mcs_idx)*2, L_prb);
    } else if (tb->mcs_idx < 14) {
      tb->mod = SRSRAN_MOD_16QAM;
      if (tb->mcs_idx < 10){
        tb->tbs = srsran_ra_tbs_from_idx(tb->mcs_idx + 5, L_prb);
      }else if (tb->mcs_idx < 14){
        tb->tbs = srsran_ra_tbs_from_idx(tb->mcs_idx + 6, L_prb);
      }
    } else if (tb->mcs_idx < 23) {
      tb->mod = SRSRAN_MOD_64QAM;
      if (tb->mcs_idx < 19){
        tb->tbs = srsran_ra_tbs_from_idx(tb->mcs_idx + 6, L_prb);
      }else if (tb->mcs_idx < 23){
        tb->tbs = srsran_ra_tbs_from_idx(tb->mcs_idx + 7, L_prb);
      }
    } else if (tb->mcs_idx < 29) {
      tb->mod = SRSRAN_MOD_256QAM;
      if (tb->mcs_idx < 26){
        tb->tbs = srsran_ra_tbs_from_idx(tb->mcs_idx + 7, L_prb);
      } else if ( tb->mcs_idx == 26 && L_prb > 0 && L_prb < 111){
        tb->tbs = tbs_table_32A[L_prb-1]; //implementation of mcs idex 32A on uplink
      }else if (tb->mcs_idx < 29){
        tb->tbs = srsran_ra_tbs_from_idx(tb->mcs_idx + 6, L_prb); 
      }
    } else {
      ERROR("Invalid MCS index %d", tb->mcs_idx);
    }
  } else if (tb->mcs_idx == 29 && cqi_request && L_prb <= 4) {
    // 8.6.1 and 8.6.2 36.213 second paragraph
    tb->mod = SRSRAN_MOD_QPSK;
    tb->tbs = 0;
    tb->rv  = 1;
  } else if (tb->mcs_idx >= 29) {
    // Else use last TBS/Modulation and use mcs to obtain rv_idx
    tb->tbs = last_tb->tbs;
    tb->mod = last_tb->mod;
    tb->rv  = tb->mcs_idx - 28;
  }
}

/** Compute PRB allocation for Uplink by using 256QAM table as defined in 8.1 and 8.4 of 36.213 */
int ulsniffer_ra_ul_dci_to_grant_256(srsran_cell_t*              cell,
                                     srsran_ul_sf_cfg_t*         sf,
                                     srsran_pusch_hopping_cfg_t* hopping_cfg,
                                     srsran_dci_ul_t*            dci,
                                     srsran_pusch_grant_t*       grant)
{
  // Compute PRB allocation
  if (!ul_sniffer_ra_ul_grant_to_grant_prb_allocation(dci, grant, hopping_cfg->n_rb_ho, cell->nof_prb)) {
    // copy default values from DCI. RV can be updated by ul_fill_ra_mcs() in case of Adaptive retx (mcs>28)
    grant->tb.mcs_idx = dci->tb.mcs_idx;
    grant->tb.rv      = dci->tb.rv;

    // Compute MCS by using 256QAM table (8.6.1-3 on 36.213)
    ul_fill_ra_mcs_256(&grant->tb, &grant->last_tb, grant->L_prb, dci->cqi_request);

    /* Compute RE assuming shortened is false*/
    srsran_ra_ul_compute_nof_re(grant, cell->cp, 0);

    // TODO: Need to compute hopping here before determining if there is collision with SRS, but only MAC knows if it's
    // a
    //  new tx or a retx. Need to split MAC interface in 2 calls. For now, assume hopping is the same
    for (uint32_t i = 0; i < 2; i++) {
      grant->n_prb_tilde[i] = grant->n_prb[i];
    }

    if (grant->nof_symb == 0 || grant->nof_re == 0) {
    //   INFO("Error converting ul_dci to grant, nof_symb=%d, nof_re=%d", grant->nof_symb, grant->nof_re);
      return SRSRAN_ERROR;
    }

    return SRSRAN_SUCCESS;
  } else {
    return SRSRAN_ERROR;
  }
}

void ul_sniffer_fill_ra_mcs(srsran_ra_tb_t* tb, srsran_ra_tb_t* last_tb, uint32_t L_prb, bool cqi_request)
{
  // 8.6.2 First paragraph
  if (tb->mcs_idx <= 28) {
    /* Table 8.6.1-1 on 36.213 */
    if (tb->mcs_idx < 11) {
      tb->mod = SRSRAN_MOD_QPSK;
      tb->tbs = srsran_ra_tbs_from_idx(tb->mcs_idx, L_prb);
    } else if (tb->mcs_idx < 21) {
      tb->mod = SRSRAN_MOD_16QAM;
      tb->tbs = srsran_ra_tbs_from_idx(tb->mcs_idx - 1, L_prb);
    } else if (tb->mcs_idx < 29) {
      tb->mod = SRSRAN_MOD_64QAM;
      tb->tbs = srsran_ra_tbs_from_idx(tb->mcs_idx - 2, L_prb);
    } else {
      ERROR("Invalid MCS index %d", tb->mcs_idx);
    }
  } else if (tb->mcs_idx == 29 && cqi_request && L_prb <= 4) {
    // 8.6.1 and 8.6.2 36.213 second paragraph
    tb->mod = SRSRAN_MOD_QPSK;
    tb->tbs = 0;
    tb->rv  = 1;
  } else if (tb->mcs_idx >= 29) {
    // Else use last TBS/Modulation and use mcs to obtain rv_idx
    tb->tbs = last_tb->tbs;
    tb->mod = last_tb->mod;
    tb->rv  = tb->mcs_idx - 28;
  }
}


int ul_sniffer_ra_ul_dci_to_grant(srsran_cell_t*              cell,
                                 srsran_ul_sf_cfg_t*         sf,
                                 srsran_pusch_hopping_cfg_t* hopping_cfg,
                                 srsran_dci_ul_t*            dci,
                                 srsran_pusch_grant_t*       grant)
{
  // Compute PRB allocation
  if (!ul_sniffer_ra_ul_grant_to_grant_prb_allocation(dci, grant, hopping_cfg->n_rb_ho, cell->nof_prb)) {
    // copy default values from DCI. RV can be updated by ul_fill_ra_mcs() in case of Adaptive retx (mcs>28)
    grant->tb.mcs_idx = dci->tb.mcs_idx;
    grant->tb.rv      = dci->tb.rv;

    // Compute MCS
    ul_sniffer_fill_ra_mcs(&grant->tb, &grant->last_tb, grant->L_prb, dci->cqi_request);

    /* Compute RE assuming shortened is false*/
    srsran_ra_ul_compute_nof_re(grant, cell->cp, 0);

    // TODO: Need to compute hopping here before determining if there is collision with SRS, but only MAC knows if it's
    // a
    //  new tx or a retx. Need to split MAC interface in 2 calls. For now, assume hopping is the same
    for (uint32_t i = 0; i < 2; i++) {
      grant->n_prb_tilde[i] = grant->n_prb[i];
    }

    if (grant->nof_symb == 0 || grant->nof_re == 0) {
    //   INFO("Error converting ul_dci to grant, nof_symb=%d, nof_re=%d", grant->nof_symb, grant->nof_re);
      return SRSRAN_ERROR;
    }

    return SRSRAN_SUCCESS;
  } else {
    return SRSRAN_ERROR;
  }
}
