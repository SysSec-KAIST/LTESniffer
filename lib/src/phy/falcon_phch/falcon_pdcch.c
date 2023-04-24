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

#include <string.h>
#include <strings.h>

#include "falcon/phy/falcon_phch/falcon_pdcch.h"

#include "srsran/phy/utils/bit.h"
#include "srsran/phy/utils/vector.h"
#include "srsran/phy/utils/debug.h"

#define PDCCH_NOF_FORMATS               4
#define PDCCH_FORMAT_NOF_CCE(i)         (1<<i)
#define PDCCH_FORMAT_NOF_REGS(i)        ((1<<i)*9)
#define PDCCH_FORMAT_NOF_BITS(i)        ((1<<i)*72)

#define NOF_CCE(cfi)  ((cfi>0&&cfi<4)?q->nof_cce[cfi-1]:0)
#define NOF_REGS(cfi) ((cfi>0&&cfi<4)?q->nof_regs[cfi-1]:0)

uint32_t srsran_pdcch_nof_cce(srsran_pdcch_t *q, uint32_t cfi) {
  return NOF_CCE(cfi);
}

/** 36.213 v9.1.1
 * Computes up to max_candidates UE-specific candidates for DCI messages and saves them
 * in the structure pointed by c.
 * Returns the number of candidates saved in the array c.
 * IMDEA contrib
 */
uint32_t srsran_pdcch_ue_locations_check(srsran_pdcch_t *q, uint32_t nsubframe, uint32_t cfi, uint16_t rnti, uint32_t this_ncce) {

  uint32_t nof_cce = NOF_CCE(cfi);
  int l; // this must be int because of the for(;;--) loop
  uint32_t i, L, m;
  uint32_t Yk, ncce;
  const unsigned int nof_candidates[4] = { 6, 6, 2, 2};

  // Compute Yk for this subframe
  Yk = rnti;
  for (m = 0; m < nsubframe+1; m++) {
      Yk = (39827 * Yk) % 65537;
    }

  // All aggregation levels from 8 to 1
  for (l = 3; l >= 0; l--) {
      L = (1 << l);
      // For all candidates as given in table 9.1.1-1
      for (i = 0; i < nof_candidates[l]; i++) {
          if (nof_cce >= L) {
              ncce = L * ((Yk + i) % (nof_cce / L));
              // Check if candidate fits in c vector and in CCE region
              if (ncce + L <= nof_cce)
                {
                  DEBUG("Trying ncce %d (%d) in UE space\n",ncce, nof_cce);
                  if (ncce==this_ncce) {
                      DEBUG("Matching NCCE (UE) %d\n",ncce);
                      return 1; // cce matches
                    }
                }
            }
        }
    }
  for (l = 3; l > 1; l--) {
      L = (1 << l);
      for (i = 0; i < SRSRAN_MIN(nof_cce, 16) / (L); i++) {
          ncce = (L) * (i % (nof_cce / (L)));
          if (ncce + L <= nof_cce)
            {
              DEBUG("Trying ncce %d in common space\n",ncce);
              if (ncce==this_ncce) {
                  DEBUG("Matching NCCE (Common) %d\n",ncce);
                  return 1; // cce matches
                }
            }
        }
    }

  DEBUG("NO Matching NCCE %d\n",this_ncce);
  return 0;
}



/** Tries to decode a DCI message from the LLRs stored in the srsran_pdcch_t structure by the function
  * srsran_pdcch_extract_llr(). This function can be called multiple times.
  * The decoded message is stored in msg and the CRC remainder in crc_rem pointer
  *
  * Note: This function is identical to srsran_pdcch_decode_msg(..., 0.5), however
  * allows other values for minimum_avg_llr_bound
  */
int srsran_pdcch_decode_msg_limit_avg_llr_power(srsran_pdcch_t *q,
                                                srsran_dci_msg_t *msg,
                                                falcon_dci_location_t *location,
                                                srsran_dci_format_t format,
                                                uint32_t cfi,
                                                uint16_t *crc_rem,
                                                double minimum_avg_llr_bound,
                                                const srsran_cell_t* cell,
                                                srsran_dl_sf_cfg_t*  sf,
                                                srsran_dci_cfg_t*    cfg)
{
  int ret = SRSRAN_ERROR_INVALID_INPUTS;
  if (q                 != NULL       &&
      msg               != NULL       &&
      falcon_dci_location_isvalid(location))
    {
      if (location->ncce * 72 + PDCCH_FORMAT_NOF_BITS(location->L) >
          NOF_CCE(cfi)*72) {
          fprintf(stderr, "Invalid location: nCCE: %d, L: %d, NofCCE: %d\n",
                  location->ncce, location->L, NOF_CCE(cfi));
        } else {
          ret = SRSRAN_SUCCESS;

          uint32_t nof_bits = srsran_dci_format_sizeof(cell, sf, cfg, format);
          uint32_t e_bits = PDCCH_FORMAT_NOF_BITS(location->L);

          double mean = 0;
          for (uint32_t i=0;i<e_bits;i++) {
              mean += fabsf(q->llr[location->ncce * 72 + i]);
            }
          mean /= e_bits;
          if (mean > minimum_avg_llr_bound) {
              ret = srsran_pdcch_dci_decode(q, &q->llr[location->ncce * 72],
                  msg->payload, e_bits, nof_bits, crc_rem);
              if (ret == SRSRAN_SUCCESS) {
                  msg->nof_bits = nof_bits;
                  // Check format differentiation
                  if (format == SRSRAN_DCI_FORMAT0 || format == SRSRAN_DCI_FORMAT1A) {
                      msg->format = (msg->payload[0] == 0)?SRSRAN_DCI_FORMAT0:SRSRAN_DCI_FORMAT1A;
                    } else {
                      msg->format   = format;
                    }
                  // adapt DL_Sniffer
                  // msg->rnti = crc_rem;
                } else {
                  fprintf(stderr, "Error calling pdcch_dci_decode\n");
                }
              if (crc_rem) {
                  DEBUG("Decoded DCI: nCCE=%d, L=%d, format=%s, msg_len=%d, mean=%f, crc_rem=0x%x\n",
                        location->ncce, location->L, srsran_dci_format_string(format), nof_bits, mean, *crc_rem);
                }
            } else {
              DEBUG("Skipping DCI:  nCCE=%d, L=%d, msg_len=%d, mean=%f\n",
                    location->ncce, location->L, nof_bits, mean);
            }
        }
    } else {
      fprintf(stderr, "Invalid parameters, location=%d,%d\n", location->ncce, location->L);
    }
  return ret;
}

/**
 * @brief srsran_pdcch_generic_locations_ncce Wrapper function for computation of DCI
 * message candidates in ue/common search space. The search space is selected by the
 * value of rnti.
 * @param nof_cce Total number of CCEs in this subframe.
 * @param c Return structure for candidates.
 * @param max_candidates Number of preallocated slots in c.
 * @param nsubframe Current subframe number 0..9
 * @param rnti RNTI for which the candidated shall be computed
 * @return Number of actually filled candidates into c.
 */
uint32_t srsran_pdcch_generic_locations_ncce(uint32_t nof_cce, srsran_dci_location_t *c, uint32_t max_candidates,
                                             uint32_t nsubframe, uint16_t rnti)
{
  if(rnti >= SRSRAN_RARNTI_START && rnti <= SRSRAN_RARNTI_END) {
    return srsran_pdcch_common_locations_ncce(nof_cce, c, max_candidates);
  }
  else if(rnti >= SRSRAN_CRNTI_START && rnti <= SRSRAN_CRNTI_END) {
    uint32_t n = 0;
    n += srsran_pdcch_ue_locations_ncce(nof_cce, c, max_candidates, nsubframe, rnti);
    n += srsran_pdcch_common_locations_ncce(nof_cce, &c[n], max_candidates - n);
    return n;
  }
  else if(rnti >= SRSRAN_MRNTI && rnti <= SRSRAN_SIRNTI) {
    return srsran_pdcch_common_locations_ncce(nof_cce, c, max_candidates);
  }
  else if(rnti > SRSRAN_CRNTI_END && rnti <= SRSRAN_MRNTI) {
    // this interval is reserved for future use
    DEBUG("Asked for rnti %d in reserved interval.\n", rnti);
    return 0;
  }

  // this should never happen
  DEBUG("rnti %d did not match to any interval.\n", rnti);
  return 0;
}

#define MAX_CANDIDATES_UE  (16+6) // From 36.213 Table 9.1.1-1 (Common+UE_spec.)

/**
 * @brief srsran_pdcch_validate_location Validate position of a DCI candidate. In addition
 * this function reports, whether the candidate for a given L has an ambiguous match for L-1
 * at the same location ncce. Deeper ambiguities L-2..3 are ignored. Ambiguous candidates require
 * special treatment to prevent coverage of neighboring DCI.
 * @param nof_cce Total number of CCEs in this subframe.
 * @param ncce Index of CCE where this DCI candidate starts
 * @param l Aggregation level of DCI candidate 0..3
 * @param nsubframe Current subframe number 0..9
 * @param rnti RNTI of the decoded candidate
 * @return 0 for invalid candidate, 1 for valid but ambiguous candidate, 2 for valid and unambiguous candidate
 */
uint32_t srsran_pdcch_validate_location(uint32_t nof_cce, uint32_t ncce, uint32_t l,
                                        uint32_t nsubframe, uint16_t rnti)
{
  uint32_t ambiguous = 0;
  uint32_t is_valid = 0;
  srsran_dci_location_t loc[MAX_CANDIDATES_UE];
  uint32_t num_candidates = srsran_pdcch_generic_locations_ncce(nof_cce, loc, MAX_CANDIDATES_UE, nsubframe, rnti);


  for(uint32_t i = 0; i < num_candidates; i++) {
    //search for matching candidate
    if(loc[i].ncce == ncce) {
      // check ambiguity
      if(l > 0 && (l-1 == loc[i].L)) {
        ambiguous = 1;
      }
      // check validity
      if(loc[i].L == l) {
        is_valid = 1;
      }
    }
  }

  if(is_valid && !ambiguous) {
    is_valid = 2;
  }
  return is_valid;
}

/** 36.213 v9.1.1
 * Computes up to max_candidates UE-specific candidates for DCI messages and saves them
 * in the structure pointed by c.
 * Returns the number of candidates saved in the array c.
 */
uint32_t srsran_pdcch_ue_locations_all(srsran_pdcch_t *q, falcon_dci_location_t *c, uint32_t max_candidates,
                                       uint32_t nsubframe, uint32_t cfi) {
  /* IMDEA contribution: obtain all possible location for CCE, without caring about the RNTI */

  uint32_t i, j, L, k;
  int l;

  k = 0;
  for (l = 3; l >= 0; l--) {
      L = (1 << l);
      for (i = 0; i < SRSRAN_MIN(NOF_CCE(cfi), MAX_NUM_OF_CCE) / (L); i++) {
          c[k].L = (uint32_t)l;
          c[k].ncce = (L) * (i % (NOF_CCE(cfi) / (L)));
          c[k].used = 0;
          c[k].checked = 0;
          c[k].sufficient_power = 1;
          if (l == 0) {
              float mean = 0;
              for (j=0;j<PDCCH_FORMAT_NOF_BITS(c[k].L);j++) {
                  mean += fabsf(q->llr[(c[k].ncce) * 72 + j]);
                }
              mean /= PDCCH_FORMAT_NOF_BITS(c[k].L);
              DEBUG("power %f\n",mean);
              c[k].power = mean;
              //if (mean > PWR_THR) {
              //	//printf("nCCE: %d, P: %f\n", c[k].ncce, mean);
              //	c[k].power = 1;
              //} else {
              //	c[k].power = 0;
              //}
            } else {
              c[k].power = 1;
            }
          DEBUG("SS Candidate %d: nCCE: %d, L: %d, P: %d\n", k, c[k].ncce, c[k].L, c[k].power);
          k++;
        }
    }
  k = 0;
  for (l = 3; l >= 0; l--) {
      L = (1 << l);
      for (i = 0; i < SRSRAN_MIN(NOF_CCE(cfi), MAX_NUM_OF_CCE) / (L); i++) {
          if (l > 0) {
              for (j=0;j<L;j++) {
                  if (c[(c[k].ncce + j + SRSRAN_MIN(NOF_CCE(cfi), MAX_NUM_OF_CCE) / (8) +  + SRSRAN_MIN(NOF_CCE(cfi), MAX_NUM_OF_CCE) / (4) +  + SRSRAN_MIN(NOF_CCE(cfi), MAX_NUM_OF_CCE) / (2))].power < PWR_THR) {
                      c[k].power = 0;
                      c[k].sufficient_power = 0;
                      break;
                    }
                }
            }
          if (c[k].power > PWR_THR) {
            DEBUG("SS Candidate %d: nCCE: %d, L: %d, P: %f\n", k, c[k].ncce, c[k].L, c[k].power);
          }
          k++;
        }
    }


  //INFO("Initiated %d candidate(s) out of %d CCEs\n", k,NOF_CCE(cfi));

  return k;
}

/* TAKEN FROM OLD VERSION _ CHECK COMPATIBILITY */
uint32_t srsran_pdcch_ue_locations_all_map(srsran_pdcch_t *q, falcon_dci_location_t *c, uint32_t max_candidates,
                                           falcon_cce_to_dci_location_map_t *cce_map, uint32_t max_cce,
                                           uint32_t nsubframe, uint32_t cfi) {
  /* IMDEA contribution: obtain all possible location for CCE, without caring about the RNTI */
  /* CNI contribution: create cce_map data structure */

  uint32_t i, L, k, map_idx;
  int l;

  k = 0;
  for (l = 3; l >= 0; l--) {
    L = (1 << l);
    for (i = 0; i < SRSRAN_MIN(NOF_CCE(cfi), MAX_NUM_OF_CCE) / (L); i++) {
      if (k < max_candidates) {
        c[k].L = (uint32_t)l;
        c[k].ncce = (L) * (i % (NOF_CCE(cfi) / (L)));
        c[k].power = 0;
        c[k].used = 0;
        c[k].occupied = 0;
        c[k].checked = 0;
        c[k].sufficient_power = 1;

        for (map_idx = c[k].ncce; map_idx < c[k].ncce + L; map_idx++) {
          cce_map[map_idx].location[l] = &c[k];
        }

        DEBUG("SS Candidate %d: nCCE: %d, L: %d\n", k, c[k].ncce, c[k].L);
        k++;
      }
    }
  }

  //INFO("Initiated %d candidate(s) out of %d CCEs\n", k,NOF_CCE(cfi));

  return k;
}

uint32_t srsran_pdcch_uncheck_ue_locations(falcon_dci_location_t *c, uint32_t nof_locations) {
  uint32_t result = 0;
  if(c) {
    for(uint32_t i=0; i<nof_locations; i++) {
      c[i].checked = 0;
    }
    result = nof_locations;
  }
  return result;
}

static float dci_decode_and_check_list(srsran_pdcch_t *q, float *e, uint8_t *data, uint32_t E, uint32_t nof_bits, uint16_t *crc, uint16_t *list) {

  uint16_t p_bits, crc_res, c_rnti;
  uint8_t *x;
  uint8_t tmp[3 * (SRSRAN_DCI_MAX_BITS + 16)];
  uint8_t tmp2[10 * (SRSRAN_DCI_MAX_BITS + 16)];
  uint8_t check[(SRSRAN_DCI_MAX_BITS + 16)];
  //srsran_convcoder_t encoder;
  //int poly[3] = { 0x6D, 0x4F, 0x57 };

  if (q         != NULL         &&
      data      != NULL         &&
      E         <= q->max_bits   &&
      nof_bits  <= SRSRAN_DCI_MAX_BITS) // &&
    //(nof_bits +16)*3 <= E) // check if it is possbile to store the dci msg in the available cces
    {
      // packet decoding

      bzero(q->rm_f, sizeof(float)*3 * (SRSRAN_DCI_MAX_BITS + 16));

      /* unrate matching */
      srsran_rm_conv_rx(e, E, q->rm_f, 3 * (nof_bits + 16));

      /* viterbi decoder */
      srsran_viterbi_decode_f(&q->decoder, q->rm_f, data, nof_bits + 16);

      if (SRSRAN_VERBOSE_ISDEBUG()) {
          srsran_bit_fprint(stdout, data, nof_bits + 16);
        }

      x = &data[nof_bits];
      p_bits = (uint16_t) srsran_bit_pack(&x, 16);
      crc_res = ((uint16_t) srsran_crc_checksum(&q->crc, data, nof_bits) & 0xffff);
      c_rnti = p_bits ^ crc_res;
      DEBUG("p_bits: 0x%x, crc_checksum: 0x%x, crc_rem: 0x%x\n", p_bits, crc_res, c_rnti);

      //    printf("op %d crnti %d\n",p_bits ^ crc_res,c_rnti);
      if (list[p_bits ^ crc_res]>0) {
          //    	printf("check ok\n");
          *crc = p_bits ^ crc_res;
          //printf("nb %d:, p_bits: 0x%x, crc_checksum: 0x%x, crc_rem: 0x%x with prob %.2f\n", nof_bits, p_bits, crc_res, c_rnti, 100.00);
          return 100.0;
        }
      else {
          // re-encoding the packet

          //encoder.K = 7;
          //encoder.R = 3;
          //encoder.tail_biting = true;
          //memcpy(encoder.poly, poly, 3 * sizeof(int));

          memcpy(check,data,nof_bits);

          //srsran_crc_attach(&q->crc, check, nof_bits);
          //crc_set_mask_rnti(&check[nof_bits], c_rnti);

          //srsran_convcoder_encode(&encoder, check, tmp, nof_bits + 16);
          srsran_pdcch_dci_encode_conv(q, check, nof_bits, tmp, c_rnti);

          srsran_rm_conv_tx(tmp, 3 * (nof_bits + 16), tmp2, E);

          float parcheck = 0.0;
          for (uint32_t i=0;i<E;i++) {
              parcheck += ((((e[i]*32+127.5)>127.5)?1:0)==tmp2[i]);
            }
          parcheck = 100*parcheck/E;

          //if (parcheck > 90) printf("nb %d:, p_bits: 0x%x, crc_checksum: 0x%x, crc_rem: 0x%x with prob %.2f\n", nof_bits, p_bits, crc_res, c_rnti, parcheck);
          *crc = p_bits ^ crc_res;
          return parcheck;
        }
    } else {
      fprintf(stderr, "Invalid parameters: E: %d, max_bits: %d, nof_bits: %d\n", E, q->max_bits, nof_bits);
      return -1.0;
    }
}

/** Tries to decode a DCI message from the LLRs stored in the srsran_pdcch_t structure by the function
 * srsran_pdcch_extract_llr(). This function can be called multiple times.
 * The decoded message is stored in msg and the CRC remainder in crc_rem pointer
 *
 */
float srsran_pdcch_decode_msg_check(srsran_pdcch_t *q,
                                    uint32_t cfi,
                                    srsran_dci_msg_t *msg,
                                    falcon_dci_location_t *location,
                                    srsran_dci_format_t format,
                                    uint16_t *crc_rem,
                                    uint16_t *list,
                                    const srsran_cell_t* cell,
                                    srsran_dl_sf_cfg_t*  sf,
                                    srsran_dci_cfg_t*    cfg)
// IMDEA contribution
{
  float ret = -1.0;

  if (q                 != NULL       &&
      msg               != NULL       &&
      falcon_dci_location_isvalid(location)  &&
      crc_rem           != NULL)
    {
      if (location->ncce * 72 + PDCCH_FORMAT_NOF_BITS(location->L) >
          NOF_CCE(cfi)*72) {
          fprintf(stderr, "Invalid location: nCCE: %d, L: %d, NofCCE: %d\n",
                  location->ncce, location->L, NOF_CCE(cfi));
        } else {
          uint32_t nof_bits = srsran_dci_format_sizeof(cell, sf, cfg, format);
          uint32_t e_bits = PDCCH_FORMAT_NOF_BITS(location->L);
          DEBUG("Decoding DCI offset %d, e_bits: %d, msg_len %d (nCCE: %d, L: %d)\n",
                location->ncce * 72, e_bits, nof_bits, location->ncce, location->L);

          ret = dci_decode_and_check_list(q, &q->llr[location->ncce * 72], msg->payload, e_bits, nof_bits, crc_rem, list);
          msg->nof_bits = nof_bits;
          // decomment the following to print the raw bits
          // for (int i=0; i< msg->nof_bits; i++) {
          //   fprintf(stdout,"%d",msg->payload[i]);
          // }
          // fprintf(stdout,"\n");
        }
    }
  return ret;
}

/** Tries to decode a DCI message from the LLRs stored in the srsran_pdcch_t structure by the function
 * srsran_pdcch_extract_llr(). This function can be called multiple times.
 * The decoded message is stored in msg and the CRC remainder in crc_rem pointer
 *
 */
float srsran_pdcch_decode_msg_check_power(srsran_pdcch_t *q,
                                          uint32_t cfi,
                                          srsran_dci_msg_t *msg,
                                          falcon_dci_location_t *location,
                                          srsran_dci_format_t format,
                                          uint16_t *crc_rem,
                                          uint16_t *list,
                                          const srsran_cell_t* cell,
                                          srsran_dl_sf_cfg_t*  sf,
                                          srsran_dci_cfg_t*    cfg)
// IMDEA contribution
{
  float ret = -1.0;

  if (q                 != NULL       &&
      msg               != NULL       &&
      falcon_dci_location_isvalid(location)  &&
      crc_rem           != NULL)
    {
      if (location->ncce * 72 + PDCCH_FORMAT_NOF_BITS(location->L) >
          NOF_CCE(cfi)*72) {
          fprintf(stderr, "Invalid location: nCCE: %d, L: %d, NofCCE: %d\n",
                  location->ncce, location->L, NOF_CCE(cfi));
        } else {
          uint32_t nof_bits = srsran_dci_format_sizeof(cell, sf, cfg, format);
          uint32_t e_bits = PDCCH_FORMAT_NOF_BITS(location->L);
          DEBUG("Decoding DCI offset %d, e_bits: %d, msg_len %d (nCCE: %d, L: %d)\n",
                location->ncce * 72, e_bits, nof_bits, location->ncce, location->L);

          float retVec[100];
          for (uint32_t i=14; i<=52; i++) {
              retVec[i] = dci_decode_and_check_list(q, &q->llr[location->ncce * 72], msg->payload, e_bits, i, crc_rem, list);
              DEBUG("nCCE: %d, L: %d, prob: %f, nof_bits %d\n",location->ncce, location->L, retVec[i], i);
              if (retVec[i] > ret) {
                  ret = retVec[i];
                  nof_bits = i;
                }
            }
          DEBUG("BEST nCCE: %d, L: %d, prob: %f, nof_bits %d\n",location->ncce, location->L, ret, nof_bits);
          ret = dci_decode_and_check_list(q, &q->llr[location->ncce * 72], msg->payload, e_bits, nof_bits, crc_rem, list);
        }
    }
  return ret;
}

uint32_t srsran_pdcch_nof_missed_cce_compat(falcon_dci_location_t *c,
                                           uint32_t nof_locations,
                                           uint32_t cfi) {
  bool* missed_cce = calloc(nof_locations, sizeof(bool));
  for(int loc_idx=0; loc_idx<nof_locations; loc_idx++) {
    if(!c[loc_idx].checked && c[loc_idx].power >= PWR_THR) {
      for(int cce_idx=0; cce_idx < (1 << c[loc_idx].L); cce_idx++) {
        missed_cce[c[loc_idx].ncce + cce_idx] = 1;
      }
    }
  }
  uint32_t result = 0;
  for(int cce_idx=0; cce_idx<nof_locations; cce_idx++) {
    if(missed_cce[cce_idx] == 1) result++;
  }
  free(missed_cce);
  return result;
}

uint32_t srsran_pdcch_nof_missed_cce(srsran_pdcch_t *q,
                                     uint32_t cfi,
                                     falcon_cce_to_dci_location_map_t *cce_map,
                                     uint32_t max_cce) {
  uint32_t ret = 0;
  if (q != NULL && cce_map != NULL) {
    for(uint32_t cce_idx = 0; cce_idx < NOF_CCE(cfi) && cce_idx < max_cce; cce_idx++) {
      if(cce_map[cce_idx].power < DCI_MINIMUM_AVG_LLR_BOUND) {
        if(SRSRAN_VERBOSE_ISINFO()) { printf("_"); }
        continue;
      }
      else {
        bool missed = true;
        for(uint32_t aggr_idx = 0; aggr_idx < 4; aggr_idx++) {
          falcon_dci_location_t* parent = cce_map[cce_idx].location[aggr_idx];
          if (parent) {
            if(parent->used) {
              missed = false;
              if(SRSRAN_VERBOSE_ISINFO()) { printf("+"); }
              break;
            }
          }
        }
        if (missed) {
          ret++;
          if(SRSRAN_VERBOSE_ISINFO()) {printf("?"); }
        }
      }
    }
  }
  if(SRSRAN_VERBOSE_ISINFO()) { printf("\n"); }
  return ret;
}

int srsran_pdcch_cce_avg_llr_power(srsran_pdcch_t *q,
                                   uint32_t cfi,
                                   falcon_cce_to_dci_location_map_t *cce_map,
                                   uint32_t max_cce) {

  int ret = SRSRAN_ERROR_INVALID_INPUTS;
  uint32_t num_cce_bits = PDCCH_FORMAT_NOF_BITS(0);
  if (q != NULL &&
      cce_map != NULL) {
      for(uint32_t cce_idx = 0; cce_idx < NOF_CCE(cfi) && cce_idx < max_cce; cce_idx++) {
          double mean = 0;
          for (int i = 0; i < num_cce_bits; i++) {
              mean += fabsf(q->llr[cce_idx * 72 + i]);
            }
          cce_map[cce_idx].power = mean / num_cce_bits;
          if(cce_map[cce_idx].power < DCI_MINIMUM_AVG_LLR_BOUND) {
              for(int aggr_idx=0; aggr_idx<4; aggr_idx++) {
                  falcon_dci_location_t* parent = cce_map[cce_idx].location[aggr_idx];
                  if(parent) parent->sufficient_power = 0;
                }
            }
        }
      ret = SRSRAN_SUCCESS;
    }
  return ret;
}

