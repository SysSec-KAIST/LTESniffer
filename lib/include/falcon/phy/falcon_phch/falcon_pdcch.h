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

#include "falcon/phy/common/falcon_phy_common.h"
#include "falcon/phy/falcon_phch/falcon_dci.h"

#ifdef __cplusplus
extern "C" {
#endif

#include "srsran/phy/phch/pdcch.h"

//#define PWR_THR				.7f >> moved to falcon_dci.h

//#define MAX_NUM_OF_CCE 64
#define MAX_NUM_OF_CCE 84

SRSRAN_API uint32_t srsran_pdcch_nof_cce(srsran_pdcch_t *q, uint32_t cfi);

SRSRAN_API float srsran_pdcch_decode_msg_check_power(srsran_pdcch_t *q,
                                          uint32_t cfi,
                                          srsran_dci_msg_t *msg,
                                          falcon_dci_location_t *location,
                                          srsran_dci_format_t format,
                                          uint16_t *crc_rem,
                                          uint16_t *list,
                                          const srsran_cell_t* cell,
                                          srsran_dl_sf_cfg_t*  sf,
                                          srsran_dci_cfg_t*    cfg);

/* Decoding functions: Try to decode a DCI message after calling srsran_pdcch_extract_llr */
SRSRAN_API float srsran_pdcch_decode_msg_check(srsran_pdcch_t *q,
                                               uint32_t cfi,
                                               srsran_dci_msg_t *msg,
                                               falcon_dci_location_t *location,
                                               srsran_dci_format_t format,
                                               uint16_t *crc_rem,
                                               uint16_t *list,
                                               const srsran_cell_t* cell,
                                               srsran_dl_sf_cfg_t*  sf,
                                               srsran_dci_cfg_t*    cfg);


/* Decoding functions: Try to decode a DCI message after calling srsran_pdcch_extract_llr */
SRSRAN_API int srsran_pdcch_decode_msg_limit_avg_llr_power(srsran_pdcch_t *q,
                                                           srsran_dci_msg_t *msg,
                                                           falcon_dci_location_t *location,
                                                           srsran_dci_format_t format,
                                                           uint32_t cfi,
                                                           uint16_t *crc_rem,
                                                           double minimum_avg_llr_bound,
                                                           const srsran_cell_t* cell,
                                                           srsran_dl_sf_cfg_t*  sf,
                                                           srsran_dci_cfg_t*    cfg);

/* Decoding functions: Try to decode a DCI message after calling srsran_pdcch_extract_llr */
SRSRAN_API int srsran_pdcch_decode_msg_no_llr_limit(srsran_pdcch_t *q,
                                                    srsran_dci_msg_t *msg,
                                                    srsran_dci_location_t *location,
                                                    srsran_dci_format_t format,
                                                    uint16_t *crc_rem);

SRSRAN_API uint32_t srsran_pdcch_nof_missed_cce_compat(falcon_dci_location_t *c,
                                           uint32_t nof_locations,
                                           uint32_t cfi);

SRSRAN_API uint32_t srsran_pdcch_nof_missed_cce(srsran_pdcch_t *q, uint32_t cfi,
                                           falcon_cce_to_dci_location_map_t *cce_map,
                                           uint32_t max_cce);

/* Calculate average power (LLR) on each CCE for DCI filtering */
SRSRAN_API int srsran_pdcch_cce_avg_llr_power(srsran_pdcch_t *q, uint32_t cfi,
                                              falcon_cce_to_dci_location_map_t *cce_map,
                                              uint32_t max_cce);


/* Function for generation of UE-specific and common search space DCI locations according to rnti */
SRSRAN_API uint32_t srsran_pdcch_generic_locations_ncce(uint32_t nof_cce,
                                                        srsran_dci_location_t *c,
                                                        uint32_t max_candidates,
                                                        uint32_t nsubframe, uint16_t rnti);

/* Validation function for DCI candidates */
SRSRAN_API uint32_t srsran_pdcch_validate_location(uint32_t nof_cce, uint32_t ncce, uint32_t l,
                                                   uint32_t nsubframe, uint16_t rnti);

SRSRAN_API uint32_t srsran_pdcch_ue_locations_all(srsran_pdcch_t *q,
                                                  falcon_dci_location_t *locations,
                                                  uint32_t max_locations,
                                                  uint32_t nsubframe,
                                                  uint32_t cfi);

SRSRAN_API uint32_t srsran_pdcch_ue_locations_all_map(srsran_pdcch_t *q,
                                                      falcon_dci_location_t *c,
                                                      uint32_t max_candidates,
                                                      falcon_cce_to_dci_location_map_t *cce_map,
                                                      uint32_t max_cce,
                                                      uint32_t nsubframe, uint32_t cfi);

SRSRAN_API uint32_t srsran_pdcch_uncheck_ue_locations(falcon_dci_location_t *c,
                                                uint32_t nof_locations);

SRSRAN_API int srsran_pdcch_decode_msg_power(srsran_pdcch_t *q,
					     srsran_dci_msg_t *msg,
					     srsran_dci_location_t *location,
					     uint32_t sfn,
					     uint32_t sf_idx);

//SRSRAN_API uint32_t srsran_pdcch_ue_locations_ncce_check(uint32_t nof_cce,
//							 uint32_t nsubframe,
//							 uint16_t rnti,
//							 uint32_t this_ncce);
SRSRAN_API uint32_t srsran_pdcch_ue_locations_check(srsran_pdcch_t *q,
						    uint32_t nsubframe,
						    uint32_t cfi,
						    uint16_t rnti,
						    uint32_t this_ncce);


#ifdef __cplusplus
}
#endif
