/*
 * LTE DL_Snifer version 1.0
 * 
 */

#pragma once

#include "falcon/common/falcon_define.h"
#include "srsran/phy/phch/dci.h"
#include "srsran/phy/phch/pdsch_cfg.h"
#include "srsran/phy/phch/ra_dl.h"
#include "srsran/phy/phch/ra.h"
#include "srsran/phy/phch/pdsch.h"
#include "srsran/phy/phch/cqi.h"

#define DL_SNIFFER_MIMO_NOT_SUPPORT -1
#define DL_SNIFFER_PMI_WRONG -2
#define DL_SNIFFER_LAYER_WRONG -3
#ifdef __cplusplus
extern "C" {
#endif

int dl_sniffer_compute_tb(bool pdsch_use_tbs_index_alt, 
                          const srsran_dci_dl_t* dci, 
                          srsran_pdsch_grant_t* grant);

int dl_sniffer_ra_dl_dci_to_grant(const srsran_cell_t*   cell,
                                  srsran_dl_sf_cfg_t*    sf,
                                  bool                   pdsch_use_tbs_index_alt,
                                  const srsran_dci_dl_t* dci,
                                  srsran_pdsch_grant_t*  grant);

int dl_sniffer_config_mimo_type(const srsran_cell_t* cell, 
                                srsran_dci_format_t format,
                                srsran_dci_dl_t *ran_dci_dl,
                                srsran_pdsch_grant_t *ran_pdsch_grant);

int dl_sniffer_config_mimo_pmi(const srsran_cell_t* cell, 
                               const srsran_dci_dl_t* dci, 
                               srsran_pdsch_grant_t* grant);

int dl_sniffer_config_mimo_layers(const srsran_cell_t* cell, 
                                  const srsran_dci_dl_t* dci, 
                                  srsran_pdsch_grant_t* grant);

int dl_sniffer_config_mimo(const srsran_cell_t* cell, 
                           srsran_dci_format_t format,
                           srsran_dci_dl_t *ran_dci_dl,
                           srsran_pdsch_grant_t *ran_pdsch_grant);

int ul_sniffer_cqi_hl_get_no_subbands(int prb);

#ifdef __cplusplus
}
#endif
