
#pragma once

#include "srsran/phy/phch/ra.h"
#include "srsran/phy/phch/dci.h"
typedef struct SRSRAN_API {
  srsran_ra_type_t alloc_type;
  union {
    srsran_ra_type0_t type0_alloc;
    srsran_ra_type1_t type1_alloc;
    srsran_ra_type2_t type2_alloc;
  };
  
  uint32_t harq_process;
  uint32_t mcs_idx;
  int      rv_idx;
  bool     ndi;
  uint32_t mcs_idx_1;
  int      rv_idx_1;
  bool     ndi_1;
  
  bool     tb_cw_swap; 
  bool     sram_id; 
  uint8_t  pinfo; 
  bool     pconf;
  bool     power_offset; 
  
  uint8_t tpc_pucch;

  bool     tb_en[2]; 

  bool     is_ra_order;
  uint32_t ra_preamble;
  uint32_t ra_mask_idx;

  bool     dci_is_1a;
  bool     dci_is_1c; 
} srsran_ra_dl_dci_t;

typedef struct SRSRAN_API {
  srsran_mod_t mod;
  int tbs;
  uint32_t idx; 
} srsran_ra_mcs_t;

typedef struct SRSRAN_API {
  bool prb_idx[2][SRSRAN_MAX_PRB];
  uint32_t nof_prb;  
  uint32_t Qm[SRSRAN_MAX_CODEWORDS];
  srsran_ra_mcs_t mcs[SRSRAN_MAX_CODEWORDS];
  srsran_sf_t sf_type;
  bool tb_en[SRSRAN_MAX_CODEWORDS];
  uint32_t pinfo;
  bool tb_cw_swap;
} srsran_ra_dl_grant_t;


typedef struct SRSRAN_API {
  uint32_t n_prb[2];
  uint32_t n_prb_tilde[2];
  uint32_t L_prb;
  uint32_t freq_hopping; 
  uint32_t M_sc; 
  uint32_t M_sc_init; 
  uint32_t Qm; 
  srsran_ra_mcs_t mcs;
  uint32_t ncs_dmrs;
} srsran_ra_ul_grant_t;

/** Unpacked DCI Format0 message */
typedef struct SRSRAN_API {
  /* 36.213 Table 8.4-2: SRSRAN_RA_PUSCH_HOP_HALF is 0 for < 10 Mhz and 10 for > 10 Mhz.
   * SRSRAN_RA_PUSCH_HOP_QUART is 00 for > 10 Mhz and SRSRAN_RA_PUSCH_HOP_QUART_NEG is 01 for > 10 Mhz.
   */
  enum {
    FALCON_RA_PUSCH_HOP_DISABLED = -1,
    FALCON_RA_PUSCH_HOP_QUART = 0,
    FALCON_RA_PUSCH_HOP_QUART_NEG = 1,
    FALCON_RA_PUSCH_HOP_HALF = 2,
    FALCON_RA_PUSCH_HOP_TYPE2 = 3,
  } freq_hop_fl;

  srsran_ra_ul_grant_t prb_alloc;

  srsran_ra_type2_t type2_alloc;
  uint32_t mcs_idx;
  uint32_t rv_idx;   
  uint32_t n_dmrs; 
  bool ndi;
  bool cqi_request;
  uint8_t tpc_pusch;

} srsran_ra_ul_dci_t;