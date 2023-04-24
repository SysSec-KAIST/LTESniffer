#pragma once

#include "falcon/common/falcon_define.h"
#include "srsran/phy/phch/dci.h"
#include "srsran/phy/phch/pdsch_cfg.h"
#include "srsran/phy/common/sequence.h"
#include "srsran/phy/phch/ra_ul.h"
#include "srsran/phy/phch/ra.h"
// #include "srsran/phy/phch/pdsch.h"
#include "srsran/phy/phch/cqi.h"

#ifdef __cplusplus
extern "C" {
#endif

int ul_fill_ra_mcs_256(srsran_ra_tb_t* tb, srsran_ra_tb_t* last_tb, uint32_t L_prb, bool cqi_request);

int ulsniffer_ra_ul_dci_to_grant_256(srsran_cell_t*              cell,
                                      srsran_ul_sf_cfg_t*         sf,
                                      srsran_pusch_hopping_cfg_t* hopping_cfg,
                                      srsran_dci_ul_t*            dci,
                                      srsran_pusch_grant_t*       grant);

int ul_sniffer_ra_ul_grant_to_grant_prb_allocation(srsran_dci_ul_t*      dci,
                                                   srsran_pusch_grant_t* grant,
                                                   uint32_t              n_rb_ho,
                                                   uint32_t              nof_prb);
int ul_sniffer_ra_ul_dci_to_grant(srsran_cell_t*              cell,
                                 srsran_ul_sf_cfg_t*         sf,
                                 srsran_pusch_hopping_cfg_t* hopping_cfg,
                                 srsran_dci_ul_t*            dci,
                                 srsran_pusch_grant_t*       grant);

#ifdef __cplusplus
}
#endif
