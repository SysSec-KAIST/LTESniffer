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

#include "falcon/common/falcon_define.h"
#include "dl_sniffer_pdsch.h"
#include "ul_sniffer_pusch.h"

#ifdef __cplusplus
extern "C" {
#endif

#include "srsran/phy/phch/dci.h"
#include "srsran/phy/phch/pdsch_cfg.h"
#include "srsran/phy/phch/ra_dl.h"
#include "srsran/phy/phch/ra_ul.h"
#include "srsran/phy/phch/pusch_cfg.h"

#define CNI_TIMESTAMP

#ifdef CNI_TIMESTAMP
#include <time.h>
#include <sys/time.h>
#endif

// IMDEA OWL's power threshold for blind decoding a set of CCEs
#define PWR_THR				.7f

// DCI minimum average llr for for blind decoding a set of CCEs
#define DCI_MINIMUM_AVG_LLR_BOUND PWR_THR
//#define DCI_MINIMUM_AVG_LLR_BOUND 0.5f     // (for testing FALCON may go downto 0.5)

// RNTI histogram and circular buffer
#define RNTI_HISTOGRAM_ELEMENT_COUNT 65536
#define RNTI_HISTORY_DEPTH_MSEC 200
#define RNTI_PER_SUBFRAME (304/5)
#define RNTI_HISTORY_DEPTH (RNTI_HISTORY_DEPTH_MSEC)*(RNTI_PER_SUBFRAME)

typedef struct {
    uint16_t* rnti_histogram;           // the actual histogram
    uint16_t* rnti_history;             // circular buffer of the recent seen RNTIs
    uint16_t* rnti_history_current;     // pointer to current head/(=foot) of rnti_history
    uint16_t* rnti_history_end;         // pointer to highest index in history array
    int rnti_history_active_users;      // number of currently active RNTIs
    int rnti_histogram_ready;           // ready-indicator, if history is filled
    uint32_t threshold;                 // threshold value for acceptance
} rnti_histogram_t;

typedef struct {
  int is_active;
  int last_seen;
  srsran_dci_format_t dci_format;
} rnti_active_set_entry_t;

typedef struct {
  rnti_active_set_entry_t entry[65536];
} rnti_active_set_t;

SRSRAN_API void rnti_histogram_init(rnti_histogram_t *h, uint32_t threshold);
SRSRAN_API void rnti_histogram_free(rnti_histogram_t *h);
SRSRAN_API void rnti_histogram_add_rnti(rnti_histogram_t *h, const uint16_t rnti);
SRSRAN_API unsigned int rnti_histogram_get_occurence(rnti_histogram_t *h, const uint16_t rnti);

SRSRAN_API void rnti_active_set_init(rnti_active_set_t *r);
SRSRAN_API void rnti_active_set_free(rnti_active_set_t *r);

typedef struct SRSRAN_API {
  srsran_dci_format_t format;
  uint32_t global_index;
  uint32_t hits;
} falcon_dci_meta_format_t;

typedef struct SRSRAN_API {
  uint32_t L;    // Aggregation level
  uint32_t ncce; // Position of first CCE of the dci
  bool used;     // Flag whether this location contains a valid dci
  bool occupied; // Flag whether this location is overlapped by a valid dci
  bool checked;  // Flag whether this location has already been processed by dci blind search
  bool sufficient_power;    // Flag if this location has enough power to carry any useful information
  float power;   // Average LLR of location (avg of cce.power)
} falcon_dci_location_t;

typedef struct SRSRAN_API {
    falcon_dci_location_t* location[4];   //overlapping location for each aggregation level. CAUTION: might be NULL
    float power;    // Average LLR in CCE
} falcon_cce_to_dci_location_map_t;

//enum for tracking 256QAM
typedef enum {
  DL_SNIFFER_64QAM_TABLE    = 0,
  DL_SNIFFER_256QAM_TABLE   = 1,
  DL_SNIFFER_UNKNOWN_TABLE  = 2,
  DL_SNIFFER_BOTH_TABLES    = 3,
  DL_SNIFFER_FULL_BUFFER    = 4
} dl_sniffer_mcs_table_t;

typedef enum {
  UL_SNIFFER_16QAM_MAX    = 0,
  UL_SNIFFER_64QAM_MAX    = 1,
  UL_SNIFFER_256QAM_MAX   = 2,
  UL_SNIFFER_UNKNOWN_MOD  = 3,
  UL_SNIFFER_BOTH_MOD     = 4,
  UL_SNIFFER_FULL_BUFFER  = 5
} ul_sniffer_mod_tracking_t;

typedef struct {
  srsran_ra_dl_dci_t   *dl_dci;
  srsran_ra_ul_dci_t   *ul_dci;
  srsran_ra_dl_grant_t *dl_grant;
  srsran_ra_ul_grant_t *ul_grant;
  srsran_dci_ul_t      *ran_ul_dci;
  srsran_pusch_grant_t *ran_ul_grant;
  srsran_pusch_grant_t *ran_ul_grant_256;
  srsran_dci_dl_t      *ran_dl_dci;
  srsran_pdsch_grant_t *ran_dl_grant;
  srsran_pdsch_grant_t *ran_dl_grant256;
} ltesniffer_dci_grant_containter_t;

SRSRAN_API int falcon_dci_index_of_format_in_list(srsran_dci_format_t format,
                                                  const srsran_dci_format_t* format_list,
                                                  const uint32_t nof_formats);

SRSRAN_API void sprint_hex(char *str, const uint32_t max_str_len, uint8_t *x, const uint32_t len);

#ifdef CNI_TIMESTAMP
// CNI contribution: provide system timestamp to log
SRSRAN_API int srsran_dci_msg_to_trace_timestamp(srsran_dci_msg_t *msg,
                   uint16_t msg_rnti,
                   uint32_t nof_prb,
                   uint32_t nof_ports,
                   ltesniffer_dci_grant_containter_t *container,
                   dl_sniffer_mcs_table_t mcs_table,
                   uint32_t sf_idx,
                   uint32_t sfn,
                   uint32_t prob,
                   uint32_t ncce,
                   uint32_t aggregation,
                   srsran_dci_format_t format,
                   uint32_t cfi,
                   float power,
                   struct timeval timestamp,
                   uint32_t histval,
                   FILE* dci_file,
                   srsran_cell_t *cell,
                   srsran_dl_sf_cfg_t* sf,
                   srsran_dci_cfg_t*   cfg,
                   srsran_pusch_hopping_cfg_t hopping_cfg);
#endif

// IMDEA contribution: this function prints the traces for the LTE sniffer either on stdout, file or both
SRSRAN_API int srsran_dci_msg_to_trace(srsran_dci_msg_t *msg,
                   uint16_t msg_rnti,
                   uint32_t nof_prb,
                   uint32_t nof_ports,
                   srsran_ra_dl_dci_t *dl_dci,
                   srsran_ra_ul_dci_t *ul_dci,
                   srsran_ra_dl_grant_t *dl_grant,
                   srsran_ra_ul_grant_t *ul_grant,
                   uint32_t sf_idx,
                   uint32_t sfn,
                   uint32_t prob,
                   uint32_t ncce,
                   uint32_t aggregation,
                   srsran_dci_format_t format,
                   uint32_t cfi,
                   float power,
                   FILE* dci_file,
                   srsran_cell_t *cell,
                   srsran_dl_sf_cfg_t* sf,
                   srsran_dci_cfg_t*   cfg);

SRSRAN_API bool falcon_dci_location_isvalid(falcon_dci_location_t *c);

SRSRAN_API void convert_dl_grant(srsran_pdsch_grant_t*   ran_dl_grant, 
                                 srsran_ra_dl_grant_t*   dl_grant, 
                                 srsran_ra_dl_dci_t  *   dl_dci);

SRSRAN_API void convert_dl_dci(srsran_dci_dl_t *ran_dl_dci, srsran_ra_dl_dci_t *dl_dci);

SRSRAN_API void convert_ul_dci(srsran_dci_ul_t *ran_ul_dci, srsran_ra_ul_dci_t *ul_dci);

SRSRAN_API void convert_ul_grant(srsran_pusch_grant_t*   ran_ul_grant, 
                                 srsran_ra_ul_grant_t*   ul_grant);

SRSRAN_API void ul_sniffer_dci_rar_unpack(uint8_t payload[SRSRAN_RAR_GRANT_LEN], srsran_dci_rar_grant_t* rar);

SRSRAN_API int ul_sniffer_dci_rar_to_ul_dci(srsran_cell_t* cell, srsran_dci_rar_grant_t* rar, srsran_dci_ul_t* dci_ul);
#ifdef __cplusplus
}
#endif
