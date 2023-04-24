/*
 * LTE DL_Snifer version 1.0
 * 
 */

#include "falcon/phy/falcon_phch/dl_sniffer_pdsch.h"

const int dl_sniffer_tbs_format1c_table[32] = {40,  56,   72,   120,  136,  144,  176,  208,  224,  256, 280,
                                              296, 328,  336,  392,  488,  552,  600,  632,  696,  776, 840,
                                              904, 1000, 1064, 1128, 1224, 1288, 1384, 1480, 1608, 1736};

/* Modulation order and transport block size determination 7.1.7 in 36.213
 * */
int dl_sniffer_compute_tb(bool pdsch_use_tbs_index_alt, const srsran_dci_dl_t* dci, srsran_pdsch_grant_t* grant)
{
  uint32_t n_prb = 0;
  int      tbs   = -1;
  uint32_t i_tbs = 0;

  // Copy info and Enable/Disable TB
  for (uint32_t i = 0; i < SRSRAN_MAX_CODEWORDS; i++) {
    grant->tb[i].mcs_idx = dci->tb[i].mcs_idx;
    grant->tb[i].rv      = dci->tb[i].rv;
    grant->tb[i].cw_idx  = dci->tb[i].cw_idx;
    if ((SRSRAN_DCI_IS_TB_EN(dci->tb[i]) && dci->format >= SRSRAN_DCI_FORMAT2) ||
        (dci->format < SRSRAN_DCI_FORMAT2 && i == 0)) {
      grant->tb[i].enabled = true;
      grant->nof_tb++;
    } else {
      grant->tb[i].enabled = false;
    }
  }

  // 256QAM table is allowed if:
  // - if the higher layer parameter altCQI-Table-r12 is configured, and
  // - if the PDSCH is assigned by a PDCCH/EPDCCH with DCI format 1/1B/1D/2/2A/2B/2C/2D with
  // - CRC scrambled by C-RNTI,
  // Otherwise, use 64QAM table (default table for R8).
  if (dci->format == SRSRAN_DCI_FORMAT1A || !SRSRAN_RNTI_ISUSER(dci->rnti)) {
    pdsch_use_tbs_index_alt = false;
  }

  if (!SRSRAN_RNTI_ISUSER(dci->rnti)) {
    if (dci->format == SRSRAN_DCI_FORMAT1A) {
      n_prb = dci->type2_alloc.n_prb1a == SRSRAN_RA_TYPE2_NPRB1A_2 ? 2 : 3;
      i_tbs = dci->tb[0].mcs_idx;
      tbs   = srsran_ra_tbs_from_idx(i_tbs, n_prb);
      if (tbs < 0) {
        INFO("Invalid TBS_index=%d or n_prb=%d", i_tbs, n_prb);
        return SRSRAN_ERROR;
      }
    } else if (dci->format == SRSRAN_DCI_FORMAT1C) {
      if (dci->tb[0].mcs_idx < 32) {
        tbs = dl_sniffer_tbs_format1c_table[dci->tb[0].mcs_idx];
      } else {
        INFO("Error decoding DCI: Invalid mcs_idx=%d in Format1C", dci->tb[0].mcs_idx);
        return SRSRAN_ERROR;
      }
    } else {
      INFO("Error decoding DCI: P/SI/RA-RNTI supports Format1A/1C only");
      //printf("DCI format: %d, RNTI: %X\n", dci->format, dci->rnti);
      return SRSRAN_ERROR;
    }
    grant->tb[0].mod = SRSRAN_MOD_QPSK;
    if (tbs >= 0) {
      grant->tb[0].tbs = (uint32_t)tbs;
    } else {
      INFO("Invalid TBS=%d", tbs);
      return SRSRAN_ERROR;
    }
  } else {
    if (dci->is_dwpts) {
      n_prb = SRSRAN_MAX(1, 0.75 * grant->nof_prb);
    } else {
      n_prb = grant->nof_prb;
    }
    for (uint32_t i = 0; i < SRSRAN_MAX_CODEWORDS; i++) {
      if (grant->tb[i].enabled) {
        grant->tb[i].tbs = srsran_dl_fill_ra_mcs(&grant->tb[i], grant->last_tbs[i], n_prb, pdsch_use_tbs_index_alt);
        if (grant->tb[i].tbs < 0) {
          char str[128];
          srsran_dci_dl_info(dci, str, sizeof(str));
          INFO("Error computing TBS from %s", str);
          return SRSRAN_ERROR;
        }
      } else {
        grant->tb[i].tbs = 0;
      }
    }
  }
  return SRSRAN_SUCCESS;
}

/** Compute the DL grant parameters  */
int dl_sniffer_ra_dl_dci_to_grant(const srsran_cell_t*   cell,
                                  srsran_dl_sf_cfg_t*    sf,
                                  bool                   pdsch_use_tbs_index_alt,
                                  const srsran_dci_dl_t* dci,
                                  srsran_pdsch_grant_t*  grant)
{
  bzero(grant, sizeof(srsran_pdsch_grant_t));

  // Compute PRB allocation
  int ret = srsran_ra_dl_grant_to_grant_prb_allocation(dci, grant, cell->nof_prb);
  if (ret == SRSRAN_SUCCESS) {
    // Compute MCS
    ret = dl_sniffer_compute_tb(pdsch_use_tbs_index_alt, dci, grant);
    if (ret == SRSRAN_SUCCESS) {
      // Compute number of RE and number of ack_value in grant
      srsran_ra_dl_compute_nof_re(cell, sf, grant);

      // Apply Section 7.1.7.3. If RA-RNTI and Format1C rv_idx=0
      if (dci->format == SRSRAN_DCI_FORMAT1C) {
        if ((SRSRAN_RNTI_ISRAR(dci->rnti)) || dci->rnti == SRSRAN_PRNTI) {
          for (uint32_t i = 0; i < SRSRAN_MAX_CODEWORDS; i++) {
            grant->tb[i].rv = 0;
          }
        }
      }
    } else {
      INFO("Configuring TB Info");
      return SRSRAN_ERROR;
    }
  } else {
    INFO("Configuring resource allocation");
    return SRSRAN_ERROR;
  }
  return ret;
    /* Config pdsch later*/
  // Configure MIMO for this TM
  // return config_mimo(cell, tm, dci, grant);
}

int dl_sniffer_config_mimo_type(const srsran_cell_t* cell, 
                                srsran_dci_format_t format,
                                srsran_dci_dl_t *ran_dci_dl,
                                srsran_pdsch_grant_t *ran_pdsch_grant
                                )
{
  switch(format) {
    case SRSRAN_DCI_FORMAT1:
    case SRSRAN_DCI_FORMAT1A:
    case SRSRAN_DCI_FORMAT1C:
      if (cell->nof_ports == 1) {
        ran_pdsch_grant->tx_scheme = SRSRAN_TXSCHEME_PORT0;
      } else {
        ran_pdsch_grant->tx_scheme = SRSRAN_TXSCHEME_DIVERSITY;
      }
      break;
    case SRSRAN_DCI_FORMAT2:
      if (ran_pdsch_grant->nof_tb == 1 && ran_dci_dl->pinfo == 0) {
        ran_pdsch_grant->tx_scheme = SRSRAN_TXSCHEME_DIVERSITY;
      } else {
        ran_pdsch_grant->tx_scheme = SRSRAN_TXSCHEME_SPATIALMUX;
      }
      break;
    case SRSRAN_DCI_FORMAT2A:
      if (ran_pdsch_grant->nof_tb == 1 && ran_dci_dl->pinfo == 0) {
        ran_pdsch_grant->tx_scheme = SRSRAN_TXSCHEME_DIVERSITY;
      } else {
        if (ran_pdsch_grant->nof_tb == 0){
          //printf("Setting CCD but en_tb = 0 \n");
        }
        ran_pdsch_grant->tx_scheme = SRSRAN_TXSCHEME_CDD;
      }
      break;

    /* Not implemented formats */
    case SRSRAN_DCI_FORMAT0:
    case SRSRAN_DCI_FORMAT1B:
    case SRSRAN_DCI_FORMAT1D:
    case SRSRAN_DCI_FORMAT2B:
    default:
      INFO("Transmission mode not supported.");
      return SRSRAN_ERROR;
  }
  return SRSRAN_SUCCESS;
}

/* Translates Precoding Information (pinfo) to Precoding matrix Index (pmi) as 3GPP 36.212 Table 5.3.3.1.5-4 */
int dl_sniffer_config_mimo_pmi(const srsran_cell_t* cell, const srsran_dci_dl_t* dci, srsran_pdsch_grant_t* grant)
{
  uint32_t nof_tb = grant->nof_tb;
  if (grant->tx_scheme == SRSRAN_TXSCHEME_SPATIALMUX) {
    if (nof_tb == 1) {
      if (dci->pinfo > 0 && dci->pinfo < 5) {
        grant->pmi = dci->pinfo - 1;
      } else {
        INFO("Not Implemented (nof_tb=%d, pinfo=%d)", nof_tb, dci->pinfo);
        return -1;
      }
    } else {
      if (dci->pinfo == 2) {
        INFO("Not implemented codebook index (nof_tb=%d (%d/%d), pinfo=%d)",
              nof_tb,
              SRSRAN_DCI_IS_TB_EN(grant->tb[0]),
              SRSRAN_DCI_IS_TB_EN(grant->tb[1]),
              dci->pinfo);
        return -1;
      } else if (dci->pinfo > 2) {
        INFO("Reserved codebook index (nof_tb=%d, pinfo=%d)", nof_tb, dci->pinfo);
        return -1;
      }
      grant->pmi = dci->pinfo % 2;
    }
  }

  return 0;
}

/* Determine number of MIMO layers */
int dl_sniffer_config_mimo_layers(const srsran_cell_t* cell, const srsran_dci_dl_t* dci, srsran_pdsch_grant_t* grant)
{
  uint32_t nof_tb = grant->nof_tb;
  switch (grant->tx_scheme) {
    case SRSRAN_TXSCHEME_PORT0:
      if (nof_tb != 1) {
        INFO("Wrong number of transport blocks (%d) for single antenna.", nof_tb);
        return SRSRAN_ERROR;
      }
      grant->nof_layers = 1;
      break;
    case SRSRAN_TXSCHEME_DIVERSITY:
      if (nof_tb != 1) {
        INFO("Wrong number of transport blocks (%d) for transmit diversity.", nof_tb);
        return SRSRAN_ERROR;
      }
      grant->nof_layers = cell->nof_ports;
      break;
    case SRSRAN_TXSCHEME_SPATIALMUX:
      if (nof_tb == 1) {
        grant->nof_layers = 1;
      } else if (nof_tb == 2) {
        grant->nof_layers = 2;
      } else {
        INFO("Wrong number of transport blocks (%d) for spatial multiplexing.", nof_tb);
        return SRSRAN_ERROR;
      }
      INFO("PDSCH configured for Spatial Multiplex; nof_codewords=%d; nof_layers=%d; pmi=%d",
           nof_tb,
           grant->nof_layers,
           grant->pmi);
      break;
    case SRSRAN_TXSCHEME_CDD:
      if (nof_tb != 2) {
        INFO("Wrong number of transport blocks (%d) for CDD.", nof_tb);
        return SRSRAN_ERROR;
      }
      grant->nof_layers = 2;
      break;
  }
  return 0;
}

int dl_sniffer_config_mimo(const srsran_cell_t* cell, 
                           srsran_dci_format_t format,
                           srsran_dci_dl_t *ran_dci_dl,
                           srsran_pdsch_grant_t *ran_pdsch_grant)
{
  if (dl_sniffer_config_mimo_type(cell, format, ran_dci_dl, ran_pdsch_grant)) {
    INFO("Configuring MIMO type");
    return DL_SNIFFER_MIMO_NOT_SUPPORT;
  }

  if (dl_sniffer_config_mimo_pmi(cell, ran_dci_dl, ran_pdsch_grant)) {
    INFO("Configuring MIMO PMI");
    return DL_SNIFFER_PMI_WRONG;
  }

  if (dl_sniffer_config_mimo_layers(cell, ran_dci_dl, ran_pdsch_grant)) {
    INFO("Configuring MIMO layers");
    return DL_SNIFFER_LAYER_WRONG;
  }

  return SRSRAN_SUCCESS;
}
int ul_cqi_hl_get_subband_size(int nof_prb){
  if (nof_prb < 7) {
    ERROR("Error: nof_prb is invalid (< 7)");
    return SRSRAN_ERROR;
  } else if (nof_prb <= 26) {
    return 4;
  } else if (nof_prb <= 63) {
    return 6;
  } else if (nof_prb <= 110) {
    return 8;
  } else {
    ERROR("Error: nof_prb is invalid (> 110)");
    return SRSRAN_ERROR;
  }

}

int ul_sniffer_cqi_hl_get_no_subbands(int nof_prb)
{
  int hl_size = ul_cqi_hl_get_subband_size(nof_prb);
  if (hl_size > 0) {
    return (int)ceil((float)nof_prb / hl_size);
  } else {
    return 0;
  }
}
