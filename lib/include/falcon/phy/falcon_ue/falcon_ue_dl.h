/*
 * Copyright (c) 2019 Robert Falkenberg.
 *
 * This file is part of FALCON 
 * (see https://github.com/falkenber9/falcon).
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * A copy of the GNU Affero General Public License can be found in
 * the LICENSE file in the top-level directory of this distribution
 * and at http://www.gnu.org/licenses/.
 */

#pragma once

#define __NEW_HISTOGRAM__

//#include "falcon/util/rnti_manager_c.h"
#include "falcon/phy/common/falcon_phy_common.h"
#include "falcon/phy/falcon_phch/falcon_dci.h"
#include "falcon/phy/falcon_phch/falcon_pdcch.h"

#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

#include "srsran/phy/ue/ue_dl.h"

#define MAX_CANDIDATES_BLIND 160
//#define POWER_ONLY
//#define LOG_ERRORS
#define PROB_THR 97


extern const srsran_dci_format_t falcon_ue_all_formats[];
extern const uint32_t nof_falcon_ue_all_formats;

#define SEARCH_SPACE_MATCH_RESULT_MISMATCH 0
#define SEARCH_SPACE_MATCH_RESULT_AMBIGUOUS 1
#define SEARCH_SPACE_MATCH_RESULT_EXACT 2
typedef struct {
  uint16_t rnti;
  srsran_dci_msg_t dci_msg;
  uint32_t search_space_match_result;
} dci_candidate_t;

typedef struct {
  srsran_dci_format_t format;
  srsran_dci_location_t loc[MAX_CANDIDATES_BLIND];
  uint32_t nof_locations;
} full_dci_blind_search_t;

typedef struct {
  uint32_t nof_locations;
  uint32_t nof_decoded_locations;
  uint32_t nof_cce;
  uint32_t nof_missed_cce;
  uint32_t nof_subframes;
  uint32_t nof_subframe_collisions_dw;
  uint32_t nof_subframe_collisions_up;
  struct timeval time_blindsearch;
} dci_blind_search_stats_t;

typedef struct SRSRAN_API {
  srsran_ue_dl_t* q;
  uint16_t rnti_list[65536];
  uint16_t rnti_cnt[65536];
  //float totRBmap_dw[10][2][110];    //subframe, layer, rb
  //float totRBmap_up[110];
  float colored_rb_map_dw_bufA[110];
  float colored_rb_map_up_bufA[110];
  float colored_rb_map_dw_bufB[110];
  float colored_rb_map_up_bufB[110];
  float* colored_rb_map_dw;
  float* colored_rb_map_up;
  float* colored_rb_map_dw_last;
  float* colored_rb_map_up_last;
  uint32_t totRBup, totRBdw, totBWup, totBWdw;
  uint16_t nof_rnti;
  uint32_t last_n_cce;

  rnti_histogram_t* rnti_histogram;  
  //srsran_dci_format_t rnti_format[RNTI_HISTOGRAM_ELEMENT_COUNT];

  falcon_dci_meta_format_t* all_meta_formats;
  falcon_dci_meta_format_t** primary_meta_formats;
  falcon_dci_meta_format_t** secondary_meta_formats;

  uint32_t nof_all_meta_formats;
  uint32_t nof_primary_meta_formats;
  uint32_t nof_secondary_meta_formats;
  bool skip_secondary_meta_formats;

  void* rnti_manager;
  void* decoderthread;

  FILE* dci_file;
  FILE* stats_file;
  dci_blind_search_stats_t stats;
  bool collision_dw, collision_up;

  //T_note: added for new downlink sniffer.
  uint16_t current_rnti;
} falcon_ue_dl_t;

SRSRAN_API int falcon_ue_dl_init(falcon_ue_dl_t *q,
                                 srsran_ue_dl_t *qq,
                                 cf_t *in_buffer[SRSRAN_MAX_PORTS],
                                 uint32_t max_prb,
                                 uint32_t nof_rx_antennas,
                                 const char* dci_file_name,
                                 const char* stats_file_name,
                                 bool skip_secondary_meta_formats,
                                 uint32_t histogramThreshold);
SRSRAN_API void falcon_ue_dl_free(falcon_ue_dl_t *q);
SRSRAN_API dci_candidate_t* falcon_alloc_candidates(uint32_t nof_candidates);
SRSRAN_API void falcon_free_candidates(dci_candidate_t* candidates);
SRSRAN_API void falcon_ue_dl_update_formats(falcon_ue_dl_t *q, double split_ratio);
SRSRAN_API void srsran_ue_dl_reset_rnti_list(falcon_ue_dl_t *q);
SRSRAN_API void srsran_ue_dl_reset_rnti_user(falcon_ue_dl_t *q, uint16_t user);
SRSRAN_API void srsran_ue_dl_reset_rnti_user_to(falcon_ue_dl_t *q, uint16_t user, uint16_t val);
SRSRAN_API void srsran_ue_dl_update_rnti_list(falcon_ue_dl_t *q);
SRSRAN_API int rnti_in_list(falcon_ue_dl_t *q, uint16_t check);
SRSRAN_API void srsran_ue_dl_stats_print(falcon_ue_dl_t *q, FILE* f);


//SRSRAN_API int srsran_ue_dl_find_dci_cc(falcon_ue_dl_t *q,
//                                        srsran_dci_msg_t *dci_msg,
//                                        uint32_t sf_idx,
//                                        uint32_t sfn);
SRSRAN_API int srsran_ue_dl_find_dci_cc(falcon_ue_dl_t *q, srsran_dci_msg_t *dci_msg,
                                        uint32_t cfi,
                                        uint32_t sf_idx,
                                        uint32_t sfn,
                                        bool reencoding_only,
                                        srsran_cell_t *cell,
                                        srsran_dl_sf_cfg_t* sf,
                                        srsran_dci_cfg_t*   cfg);

SRSRAN_API int srsran_ue_dl_inspect_dci_location_recursively( falcon_ue_dl_t *q,
                                                              srsran_dci_msg_t *dci_msg,
                                                              uint32_t cfi,
                                                              uint32_t sf_idx,
                                                              uint32_t sfn,
                                                              falcon_cce_to_dci_location_map_t *cce_map,
                                                              falcon_dci_location_t *location_list,
                                                              uint32_t ncce,
                                                              uint32_t L,
                                                              uint32_t max_depth,
                                                              falcon_dci_meta_format_t** meta_formats,
                                                              uint32_t nof_formats,
                                                              uint32_t enable_discovery,
                                                              const dci_candidate_t parent_rnti_cand[],
                                                              srsran_cell_t *cell,
                                                              srsran_dl_sf_cfg_t* sf,
                                                              srsran_dci_cfg_t*   cfg);

SRSRAN_API int srsran_ue_dl_recursive_blind_dci_search( falcon_ue_dl_t *q,
                                                        srsran_dci_msg_t *dci_msg,
                                                        uint32_t cfi,
                                                        uint32_t sf_idx,
                                                        uint32_t sfn,
                                                        srsran_cell_t *cell,
                                                        srsran_dl_sf_cfg_t* sf,
                                                        srsran_dci_cfg_t*   cfg);

SRSRAN_API int srsran_ue_dl_find_dci_histogram( falcon_ue_dl_t *q,
                                                srsran_dci_msg_t *dci_msg,
                                                uint32_t cfi,
                                                uint32_t sf_idx,
                                                uint32_t sfn,
                                                srsran_cell_t *cell,
                                                srsran_dl_sf_cfg_t* sf,
                                                srsran_dci_cfg_t*   cfg);

SRSRAN_API int srsran_ue_dl_get_control_cc( falcon_ue_dl_t *q,
                                            uint32_t sf_idx,
                                            uint32_t sfn,
                                            bool reencoding_only,
                                            srsran_cell_t *cell,
                                            srsran_dl_sf_cfg_t* sf,
                                            srsran_dci_cfg_t*   cfg);

SRSRAN_API int srsran_ue_dl_get_control_cc_hist(falcon_ue_dl_t *q,
                                                uint32_t sf_idx,
                                                uint32_t sfn,
                                                srsran_cell_t *cell,
                                                srsran_dl_sf_cfg_t* sf,
                                                srsran_dci_cfg_t*   cfg);

#ifdef __cplusplus
}
#endif
