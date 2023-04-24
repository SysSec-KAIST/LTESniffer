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

//#include "src/gui/plot_data.h" //MoHACKS

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>


#include "falcon/phy/falcon_phch/falcon_dci.h"
#include "falcon/phy/common/falcon_phy_common.h"

#include "srsran/phy/utils/bit.h"
#include "srsran/phy/utils/debug.h"
//#define ENABLE_DCI_LOGGING

void sprint_hex(char *str, const uint32_t max_str_len, uint8_t *x, const uint32_t len) {
  uint32_t i, nbytes;
  uint8_t byte;
  nbytes = len/8;
  // check that hex string fits in buffer (every byte takes 2 characters)
  if ((2*(len/8 + ((len%8)?1:0))) >= max_str_len) {
    ERROR("Buffer too small for printing hex string (max_str_len=%d, payload_len=%d).\n", max_str_len, len);
    return;
  }

  int n=0;
  for (i=0;i<nbytes;i++) {
    byte = (uint8_t) srsran_bit_pack(&x, 8);
    n+=sprintf(&str[n], "%02x", byte);
  }
  if (len%8) {
    byte = (uint8_t) srsran_bit_pack(&x, len%8)<<(8-(len%8));
    n+=sprintf(&str[n], "%02x", byte);
  }
  str[n] = 0;
  str[max_str_len-1] = 0;
}

void sscan_hex(const char *str, uint8_t *x, const uint32_t len) {
  size_t str_len = strlen(str);
  uint8_t byte;

  if( (2*(len/8 + (len%8?1:0))) > str_len ) {
    ERROR("Hex string too short (%ld byte) to fill bit string of length %d", str_len, len);
    return;
  }

  int pos=0;
  for(uint32_t n=0; n<len; n+=8) {
    sscanf(&str[pos], "%02hhx", &byte); // read two chars (as hex)
    pos += 2;
    srsran_bit_unpack(byte, &x, 8);
  }
  if(len%8) {
    sscanf(&str[pos], "%02hhx", &byte);
    srsran_bit_unpack(byte<<(8-(len%8)), &x, len%8);
  }

}

SRSRAN_API void rnti_histogram_init(rnti_histogram_t *h, uint32_t threshold) {

  // init histogram
  h->rnti_histogram = calloc(RNTI_HISTOGRAM_ELEMENT_COUNT, sizeof(uint16_t));
  //memset(h->rnti_histogram, 0, sizeof(h->rnti_histogram));

  // init history circular buffer
  h->rnti_history = calloc(RNTI_HISTORY_DEPTH, sizeof(uint16_t));
  h->rnti_history_current = h->rnti_history;
  h->rnti_history_end = h->rnti_history+(RNTI_HISTORY_DEPTH)-1;
  //memset(h->rnti_history, 0, sizeof(h->rnti_history));

  h->rnti_history_active_users = 0;
  h->rnti_histogram_ready = 0;
  h->threshold = threshold;
}

SRSRAN_API void rnti_histogram_free(rnti_histogram_t *h) {
  if(h) {
    free(h->rnti_histogram);
    free(h->rnti_history);
    h->rnti_histogram = 0;
    h->rnti_history = 0;
    h->rnti_history_active_users = 0;
    h->rnti_histogram_ready = 0;
  }
}

SRSRAN_API void rnti_histogram_add_rnti(rnti_histogram_t *h, const uint16_t new_rnti) {
  if(h->rnti_histogram_ready) {
    if(h->rnti_histogram[*h->rnti_history_current] == h->threshold) {  // this rnti is no longer in use, decrement active user counter
      h->rnti_history_active_users--;
    }
    h->rnti_histogram[*h->rnti_history_current]--;    // decrement occurence counter for old rnti
    //printf("Decremented RNTI %d to %d\n", *h->rnti_history_current, h->rnti_histogram[*h->rnti_history_current]);
  }
  *h->rnti_history_current = new_rnti;               // add new rnti to history
  h->rnti_histogram[new_rnti]++;                     // increment occurence counter for new rnti
  if(h->rnti_histogram[new_rnti] == h->threshold) {  // this rnti reaches threshold -> increment active user counter
    h->rnti_history_active_users++;
  }

  if(h->rnti_history_current == h->rnti_history_end) {  // set current to next element in history
    h->rnti_histogram_ready = 1;                   // first wrap around: histogram is ready now
    h->rnti_history_current = h->rnti_history;
  }
  else {
    h->rnti_history_current++;
  }
}

SRSRAN_API unsigned int rnti_histogram_get_occurence(rnti_histogram_t *h, const uint16_t rnti) {
  return h->rnti_histogram[rnti];
}

int falcon_dci_index_of_format_in_list(srsran_dci_format_t format,
                                       const srsran_dci_format_t* format_list,
                                       const uint32_t nof_formats) {
  for(uint32_t idx=0; idx<nof_formats; idx++) {
    if(format == format_list[idx]) return (int)idx;
  }
  return -1;
}

#ifdef CNI_TIMESTAMP
// CNI contribution: provide system timestamp to log
int srsran_dci_msg_to_trace_timestamp(srsran_dci_msg_t *msg,
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
                                      srsran_dci_cfg_t*   dci_cfg,
                                      srsran_pusch_hopping_cfg_t hopping_cfg)
{
  int ret = SRSRAN_ERROR_INVALID_INPUTS;
  bool crc_is_crnti;

  if (msg               !=  NULL) {

    ret = SRSRAN_ERROR;

    char hex_str[SRSRAN_DCI_MAX_BITS/4 + 1];
    sprint_hex(hex_str, sizeof(hex_str), msg->payload, msg->nof_bits);

#if 0 // Verify pack/unpack hex strings
    uint8_t dci_bits[SRSRAN_DCI_MAX_BITS];
    sscan_hex(hex_str, dci_bits, msg->nof_bits);
    for(int kk = 0; kk<msg->nof_bits; kk++) {
      if(dci_bits[kk] != msg->data[kk]) {
        ERROR("Mismatch in re-unpacked hex strings");
      }
    }
#endif

    bzero(container->ul_dci, sizeof(srsran_ra_ul_dci_t));
    bzero(container->ul_grant, sizeof(srsran_ra_ul_grant_t));
    bzero(container->dl_dci, sizeof(srsran_ra_dl_dci_t));
    bzero(container->dl_grant, sizeof(srsran_ra_dl_grant_t));
    bzero(container->ran_ul_grant, sizeof(srsran_pusch_grant_t));
    bzero(container->ran_ul_grant_256, sizeof(srsran_pusch_grant_t));
    bzero(container->ran_ul_dci, sizeof(srsran_dci_ul_t));
    // bzero(ran_dl_dci, sizeof(srsran_dci_dl_t));
    // bzero(ran_dl_grant, sizeof(srsran_pdsch_grant_t));
    crc_is_crnti = false;

    if (msg_rnti >= SRSRAN_CRNTI_START && msg_rnti <= SRSRAN_CRNTI_END) {
      crc_is_crnti = true;
    }

    if (format==SRSRAN_DCI_FORMAT0) {

      if (msg->payload[0]==0) {
        if (srsran_dci_msg_unpack_pusch(cell, sf, dci_cfg, msg, container->ran_ul_dci)) {
          container->ran_ul_dci->rnti = 0;
          DEBUG("Can't unpack UL DCI message: most likely SPS\n");
          return ret;
        }

        /* convert ran_ul_dci to falcon_ul_dci */
        convert_ul_dci(container->ran_ul_dci, container->ul_dci);

        srsran_ul_sf_cfg_t ul_sf;
        bzero(&ul_sf, sizeof(srsran_ul_sf_cfg_t));
        ul_sf.shortened = false;
        ul_sf.tdd_config = sf->tdd_config;
        ul_sf.tti = sf->tti;
        if (srsran_ra_ul_dci_to_grant(cell, &ul_sf, &hopping_cfg, container->ran_ul_dci, container->ran_ul_grant)) {
          container->ran_ul_dci->rnti = 0;
          INFO("Invalid uplink resource allocation\n");
          return ret;
        }
        if (ulsniffer_ra_ul_dci_to_grant_256(cell, &ul_sf, &hopping_cfg, container->ran_ul_dci, container->ran_ul_grant_256)) {
          container->ran_ul_dci->rnti = 0;
          INFO("Invalid uplink resource allocation\n");
          return ret;
        }
        convert_ul_grant(container->ran_ul_grant, container->ul_grant);

        if (crc_is_crnti == true) {
          if (container->ul_dci->mcs_idx < 29) {
#ifdef ENABLE_DCI_LOGGING
            fprintf(dci_file, "%ld.%06ld\t%04d\t%d\t%d\t0\t"
                            "%d\t%d\t%d\t%d\t%d\t"
                            "0\t%d\t-1\t%d\t"
                            "%d\t%d\t%d\t%d\t%d\t%s\n", timestamp.tv_sec, timestamp.tv_usec, sfn, sf_idx, msg_rnti,
                    ul_grant->mcs.idx, ul_grant->L_prb, ul_grant->mcs.tbs, -1, -1,
                    container->ul_dci->ndi, (10*sfn+sf_idx)%8,
                    ncce, aggregation, cfi, histval, msg->nof_bits, hex_str);
#endif
          }
          else {
#ifdef ENABLE_DCI_LOGGING
            fprintf(dci_file, "%ld.%06ld\t%04d\t%d\t%d\t0\t"
                            "%d\t%d\t%d\t%d\t%d\t"
                            "0\t%d\t-1\t%d\t"
                            "%d\t%d\t%d\t%d\t%d\t%s\n", timestamp.tv_sec, timestamp.tv_usec, sfn, sf_idx, msg_rnti,
                    ul_grant->mcs.idx, ul_grant->L_prb, 0, -1, -1,
                    container->ul_dci->ndi, (10*sfn+sf_idx)%8,
                    ncce, aggregation, cfi, histval, msg->nof_bits, hex_str);
#endif
          }
        }
        else {
          INFO("Invalid RNTI for uplink\n");
          return ret;
        }
        ret = SRSRAN_SUCCESS;
      }
      else {
        ERROR("wrong upload\n");
      }
    }
    else {
      msg->format = format;

      if (srsran_dci_msg_unpack_pdsch(cell, sf, dci_cfg, msg, container->ran_dl_dci)) { // maybe move inside previous if
        DEBUG("Can't unpack DL DCI message: most likely SPS\n");
        return ret;
      }
      convert_dl_dci(container->ran_dl_dci, container->dl_dci);

      // CNI Fix:
      // dci_to_grant function returns SRSRAN_ERROR in case of HARQ retransmission.
      // Prior versions of SRSRAN have saved and restored TBS for the associated
      // HARQ process instead with the help of global variables.
      // To maintain OWLs behaviour, we mimic this behaviour here
      
      // 256QAM mcs table
      if (mcs_table == DL_SNIFFER_64QAM_TABLE){
        if (dl_sniffer_ra_dl_dci_to_grant(cell, sf, DL_SNIFFER_64QAM_TABLE, container->ran_dl_dci, container->ran_dl_grant)!=SRSRAN_SUCCESS) {
          container->ran_dl_dci->rnti = 0; //covert to RNTI 0 to avoid decode
          INFO("dl_sniffer_ra_dl_dci_to_grant did not return SRSRAN_SUCCESS. Probably HARQ or illegal RB alloc\n");
          //do not return error here. Instead continue due to SRSRAN BUG #318
        }
        convert_dl_grant(container->ran_dl_grant, container->dl_grant, container->dl_dci);
      } else if (mcs_table == DL_SNIFFER_256QAM_TABLE){
        if (dl_sniffer_ra_dl_dci_to_grant(cell, sf, DL_SNIFFER_256QAM_TABLE, container->ran_dl_dci, container->ran_dl_grant256)!=SRSRAN_SUCCESS) {
          container->ran_dl_dci->rnti = 0; //covert to RNTI 0 to avoid decode
          INFO("dl_sniffer_ra_dl_dci_to_grant did not return SRSRAN_SUCCESS. Probably HARQ or illegal RB alloc\n");
          //do not return error here. Instead continue due to SRSRAN BUG #318
        }
        convert_dl_grant(container->ran_dl_grant256, container->dl_grant, container->dl_dci);
      } else {
        if (dl_sniffer_ra_dl_dci_to_grant(cell, sf, DL_SNIFFER_64QAM_TABLE, container->ran_dl_dci, container->ran_dl_grant)!=SRSRAN_SUCCESS) {
          container->ran_dl_dci->rnti = 0; //covert to RNTI 0 to avoid decode
          INFO("dl_sniffer_ra_dl_dci_to_grant did not return SRSRAN_SUCCESS. Probably HARQ or illegal RB alloc\n");
          //do not return error here. Instead continue due to SRSRAN BUG #318
        }
        if (dl_sniffer_ra_dl_dci_to_grant(cell, sf, DL_SNIFFER_256QAM_TABLE, container->ran_dl_dci, container->ran_dl_grant256)!=SRSRAN_SUCCESS) {
          container->ran_dl_dci->rnti = 0; //covert to RNTI 0 to avoid decode
          INFO("dl_sniffer_ra_dl_dci_to_grant did not return SRSRAN_SUCCESS. Probably HARQ or illegal RB alloc\n");
          //do not return error here. Instead continue due to SRSRAN BUG #318
        }
        convert_dl_grant(container->ran_dl_grant, container->dl_grant, container->dl_dci);
      }
      switch(msg->format) {
        case SRSRAN_DCI_FORMAT0:
          ERROR("Error: no reason to be here\n");
          break;
        case SRSRAN_DCI_FORMAT1:
        case SRSRAN_DCI_FORMAT1A:
        case SRSRAN_DCI_FORMAT1C:
        case SRSRAN_DCI_FORMAT1B:
        case SRSRAN_DCI_FORMAT1D:
#ifdef ENABLE_DCI_LOGGING
          fprintf(dci_file, "%ld.%06ld\t%04d\t%d\t%d\t1\t"
                          "%d\t%d\t%d\t%d\t%d\t"
                          "%d\t%d\t%d\t%d\t"
                          "%d\t%d\t%d\t%d\t%d\t%s\n", timestamp.tv_sec, timestamp.tv_usec, sfn, sf_idx, msg_rnti,
                  dl_grant->mcs[0].idx, dl_grant->nof_prb, dl_grant->mcs[0].tbs, -1, -1,
              msg->format+1, dl_dci->ndi, -1, dl_dci->harq_process,
              ncce, aggregation, cfi, histval, msg->nof_bits, hex_str);
#endif
          break;
        case SRSRAN_DCI_FORMAT2:
        case SRSRAN_DCI_FORMAT2A:
        case SRSRAN_DCI_FORMAT2B:
#ifdef ENABLE_DCI_LOGGING
          fprintf(dci_file, "%ld.%06ld\t%04d\t%d\t%d\t1\t"
                          "%d\t%d\t%d\t%d\t%d\t"
                          "%d\t%d\t%d\t%d\t"
                          "%d\t%d\t%d\t%d\t%d\t%s\n", timestamp.tv_sec, timestamp.tv_usec, sfn, sf_idx, msg_rnti,
                  dl_grant->mcs[0].idx, dl_grant->nof_prb, dl_grant->mcs[0].tbs + dl_grant->mcs[1].tbs, dl_grant->mcs[0].tbs, dl_grant->mcs[1].tbs,
              msg->format+1, dl_dci->ndi, dl_dci->ndi_1, dl_dci->harq_process,
              ncce, aggregation, cfi, histval, msg->nof_bits, hex_str);
#endif
          break;
          //case SRSRAN_DCI_FORMAT3:
          //case SRSRAN_DCI_FORMAT3A:
        default:
          ERROR("Other formats\n");
      }
      ret = SRSRAN_SUCCESS;
    }
  }
  return ret;
}
#endif

// IMDEA contribution: this function prints the traces for the LTE sniffer either on stdout, file or both
int srsran_dci_msg_to_trace(srsran_dci_msg_t *msg,
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
                            srsran_dci_cfg_t*   dci_cfg)
{
  int ret = SRSRAN_ERROR_INVALID_INPUTS;
  bool crc_is_crnti;

  if (msg               !=  NULL) {

    ret = SRSRAN_ERROR;

    bzero(ul_dci, sizeof(srsran_ra_ul_dci_t));
    bzero(ul_grant, sizeof(srsran_ra_ul_grant_t));
    bzero(dl_dci, sizeof(srsran_ra_dl_dci_t));
    bzero(dl_grant, sizeof(srsran_ra_dl_grant_t));
    crc_is_crnti = false;

    if (msg_rnti >= SRSRAN_CRNTI_START && msg_rnti <= SRSRAN_CRNTI_END) {
      crc_is_crnti = true;
    }

    if (format==SRSRAN_DCI_FORMAT0) {

      srsran_dci_ul_t ran_ul_dci;
      bzero(&ran_ul_dci, sizeof(srsran_dci_ul_t));

      if (msg->payload[0]==0) {
        if (srsran_dci_msg_unpack_pusch(cell, sf, dci_cfg, msg, &ran_ul_dci)) {
          DEBUG("Can't unpack UL DCI message: most likely SPS\n");
          return ret;
        }

        /* Convert ran_ul_mgs to falcon_ul_mgs*/
        convert_ul_dci(&ran_ul_dci, ul_dci);

        // if (srsran_ra_ul_dci_to_grant(ul_dci, nof_prb, 0, ul_grant)) {
        //   INFO("Invalid uplink resource allocation\n");
        //   return ret;
        // }

        if (crc_is_crnti == true) {
          if (ul_dci->mcs_idx < 29) {
            fprintf(dci_file, "%04d\t%d\t%d\t0\t"
                            "%d\t%d\t%d\t%d\t%d\t"
                            "0\t%d\t-1\t%d\t"
                            "%d\t%d\t%d\t%d\n", sfn, sf_idx, msg_rnti,
                    ul_grant->mcs.idx, ul_grant->L_prb, ul_grant->mcs.tbs, -1, -1,
                    ul_dci->ndi, (10*sfn+sf_idx)%8,
                    ncce, aggregation, cfi, prob);
          }
          else {
            fprintf(dci_file, "%04d\t%d\t%d\t0\t"
                            "%d\t%d\t%d\t%d\t%d\t"
                            "0\t%d\t-1\t%d\t"
                            "%d\t%d\t%d\t%d\n", sfn, sf_idx, msg_rnti,
                    ul_grant->mcs.idx, ul_grant->L_prb, 0, -1, -1,
                    ul_dci->ndi, (10*sfn+sf_idx)%8,
                    ncce, aggregation, cfi, prob);
          }
        }
        else {
          INFO("Invalid RNTI for uplink\n");
          return ret;
        }
        ret = SRSRAN_SUCCESS;
      }
      else {
        ERROR("wrong upload\n");
      }
    }
    else {
      msg->format = format;
      srsran_dci_dl_t    ran_dl_dci;
      bzero(&ran_dl_dci, sizeof(srsran_dci_dl_t));
      if (srsran_dci_msg_unpack_pdsch(cell, sf, dci_cfg, msg, &ran_dl_dci)) { // maybe move inside previous if
        DEBUG("Can't unpack DL DCI message: most likely SPS\n");
        return ret;
      }
      convert_dl_dci(&ran_dl_dci, dl_dci);

      // CNI Fix:
      // dci_to_grant function returns SRSRAN_ERROR in case of HARQ retransmission.
      // Prior versions of SRSRAN have saved and restored TBS for the associated
      // HARQ process instead with the help of global variables.
      // To maintain OWLs behaviour, we mimic this behaviour here

      srsran_pdsch_grant_t  ran_dl_grant;
      bzero(&ran_dl_grant, sizeof(srsran_pdsch_grant_t));
      //random TM to be fit with function
      bool tbs_alter = dl_dci->tb_cw_swap;
      if (dl_sniffer_ra_dl_dci_to_grant(cell, sf, tbs_alter, &ran_dl_dci, &ran_dl_grant)!=SRSRAN_SUCCESS) {
        INFO("dl_sniffer_ra_dl_dci_to_grant did not return SRSRAN_SUCCESS. Probably HARQ or illegal RB alloc\n");
        //do not return error here. Instead continue due to SRSRAN BUG #318
      }
      convert_dl_grant(&ran_dl_grant, dl_grant, dl_dci);
      
      if(crc_is_crnti == true) {  // HARQ only for C-RNTI
        // We know, last_dl_tbs needs to be saved on a per-RNTI basis.
        // However, we maintain OWLs initial behaviour here
        static int32_t last_dl_tbs[8][SRSRAN_MAX_CODEWORDS] = {{0}};

        // Set last TBS for this TB (pid) in case of mcs>28 (7.1.7.2 of 36.213)
        for (int i=0;i<SRSRAN_MAX_CODEWORDS;i++) {
          if (dl_grant->mcs[i].idx > 28) {
            dl_grant->mcs[i].tbs = last_dl_tbs[dl_dci->harq_process][i];
          }
          if(dl_grant->mcs[i].tbs < 0) {
            ERROR("Invalid TBS size for PDSCH grant\n");
            dl_grant->mcs[i].tbs = 0;
          }
          // save it for next time
          last_dl_tbs[dl_dci->harq_process][i] = dl_grant->mcs[i].tbs;
        }
      }
      // End CNI Fix
      switch(msg->format) {
        case SRSRAN_DCI_FORMAT0:
          ERROR("Error: no reason to be here\n");
          break;
        case SRSRAN_DCI_FORMAT1:
        case SRSRAN_DCI_FORMAT1A:
        case SRSRAN_DCI_FORMAT1C:
        case SRSRAN_DCI_FORMAT1B:
        case SRSRAN_DCI_FORMAT1D:
          fprintf(dci_file, "%04d\t%d\t%d\t1\t"
                          "%d\t%d\t%d\t%d\t%d\t"
                          "%d\t%d\t%d\t%d\t"
                          "%d\t%d\t%d\t%d\n", sfn, sf_idx, msg_rnti,
                  dl_grant->mcs[0].idx, dl_grant->nof_prb, dl_grant->mcs[0].tbs, -1, -1,
              msg->format+1, dl_dci->ndi, -1, dl_dci->harq_process,
              ncce, aggregation, cfi, prob);
          break;
        case SRSRAN_DCI_FORMAT2:
        case SRSRAN_DCI_FORMAT2A:
        case SRSRAN_DCI_FORMAT2B:
          fprintf(dci_file, "%04d\t%d\t%d\t1\t"
                          "%d\t%d\t%d\t%d\t%d\t"
                          "%d\t%d\t%d\t%d\t"
                          "%d\t%d\t%d\t%d\n", sfn, sf_idx, msg_rnti,
                  dl_grant->mcs[0].idx, dl_grant->nof_prb, dl_grant->mcs[0].tbs + dl_grant->mcs[1].tbs, dl_grant->mcs[0].tbs, dl_grant->mcs[1].tbs,
              msg->format+1, dl_dci->ndi, dl_dci->ndi_1, dl_dci->harq_process,
              ncce, aggregation, cfi, prob);
          break;
          //case SRSRAN_DCI_FORMAT3:
          //case SRSRAN_DCI_FORMAT3A:
        default:
          ERROR("Other formats\n");
      }
      ret = SRSRAN_SUCCESS;
    }
  }
  return ret;
}

bool falcon_dci_location_isvalid(falcon_dci_location_t *c) {
  if (c->L <= 3 && c->ncce <= 87) {
    return true;
  }
  else {
    return false;
  }
}

void convert_ul_dci(srsran_dci_ul_t *ran_ul_dci, srsran_ra_ul_dci_t *ul_dci){
  ul_dci->freq_hop_fl     = ran_ul_dci->freq_hop_fl;
  // ul prb_alloc
  ul_dci->type2_alloc     = ran_ul_dci->type2_alloc;
  ul_dci->mcs_idx         = ran_ul_dci->tb.mcs_idx;
  ul_dci->rv_idx          = ran_ul_dci->tb.rv;
  ul_dci->n_dmrs          = ran_ul_dci->n_dmrs;
  ul_dci->ndi             = ran_ul_dci->tb.ndi;
  ul_dci->cqi_request     = ran_ul_dci->cqi_request;
  ul_dci->tpc_pusch       = ran_ul_dci->tpc_pusch;
}

void convert_dl_dci(srsran_dci_dl_t *ran_dl_dci, srsran_ra_dl_dci_t *dl_dci){
  dl_dci->alloc_type = ran_dl_dci->alloc_type;

  dl_dci->mcs_idx = ran_dl_dci->tb[0].mcs_idx;
  dl_dci->rv_idx  = ran_dl_dci->tb[0].rv;
  dl_dci->ndi     = ran_dl_dci->tb[0].ndi;

  dl_dci->mcs_idx_1 = ran_dl_dci->tb[1].mcs_idx;
  dl_dci->rv_idx_1  = ran_dl_dci->tb[1].rv;
  dl_dci->ndi_1     = ran_dl_dci->tb[1].ndi;

  dl_dci->harq_process  = ran_dl_dci->pid;

  dl_dci->tb_cw_swap    = ran_dl_dci->tb_cw_swap;
  dl_dci->sram_id       = ran_dl_dci->sram_id;
  dl_dci->pinfo         = ran_dl_dci->pinfo;
  dl_dci->pconf         = ran_dl_dci->pconf;
  dl_dci->power_offset  = ran_dl_dci->power_offset;
  dl_dci->tpc_pucch     = ran_dl_dci->tpc_pucch;

  dl_dci->is_ra_order = ran_dl_dci->is_ra_order;
  dl_dci->ra_preamble = ran_dl_dci->ra_preamble;
  dl_dci->ra_mask_idx = ran_dl_dci->ra_mask_idx;
  if (ran_dl_dci->format == SRSRAN_DCI_FORMAT1A){
    dl_dci->dci_is_1a = true;
  }else if (ran_dl_dci->format == SRSRAN_DCI_FORMAT1C){
    dl_dci->dci_is_1c = true;
  }
  //tb-en
  if (dl_dci->mcs_idx == 0 && dl_dci->rv_idx == 1) {
    dl_dci->tb_en[0] = false; 
  } else {
    dl_dci->tb_en[0] = true; 
  }
  // same for tb1
  if (dl_dci->mcs_idx_1 == 0 && dl_dci->rv_idx_1 == 1) {
    dl_dci->tb_en[1] = false; 
  } else {
    dl_dci->tb_en[1] = true; 
  }
}

void convert_dl_grant(srsran_pdsch_grant_t*   ran_dl_grant, 
                      srsran_ra_dl_grant_t*   dl_grant, 
                      srsran_ra_dl_dci_t  *   dl_dci)
{
  for (int i = 0; i < 2; i++){
    for (int j = 0; j < SRSRAN_MAX_PRB; j++){
      dl_grant->prb_idx[i][j] = ran_dl_grant->prb_idx[i][j];
    }
  }
  dl_grant->nof_prb = ran_dl_grant->nof_prb;
  
  //Qm
  for (int tb = 0; tb < SRSRAN_MAX_CODEWORDS; tb++) {
  if (dl_dci->tb_en[tb]) {
    dl_grant->Qm[tb] = srsran_mod_bits_x_symbol(dl_grant->mcs[tb].mod);
  }
  }

  for (int i = 0; i < SRSRAN_MAX_CODEWORDS; i++){
    dl_grant->mcs[i].idx = ran_dl_grant->tb[i].mcs_idx;
    dl_grant->mcs[i].mod = ran_dl_grant->tb->mod;
    dl_grant->mcs[i].tbs = ran_dl_grant->tb->tbs;
  }
  dl_grant->sf_type = SRSRAN_SF_NORM;
  //tb_en
  if (dl_dci->mcs_idx == 0 && dl_dci->rv_idx == 1) {
    dl_grant->tb_en[0] = false; 
  } else {
    dl_grant->tb_en[0] = true; 
  }
  // same for tb1
  if (dl_dci->mcs_idx_1 == 0 && dl_dci->rv_idx_1 == 1) {
    dl_grant->tb_en[1] = false; 
  } else {
    dl_grant->tb_en[1] = true; 
  }
  dl_grant->pinfo = dl_dci->pinfo;
  dl_grant->tb_cw_swap = dl_dci->tb_cw_swap;
}

void convert_ul_grant(srsran_pusch_grant_t*   ran_ul_grant, 
                      srsran_ra_ul_grant_t*   ul_grant)
{
  ul_grant->freq_hopping = ran_ul_grant->freq_hopping;
  for (auto i = 0; i < SRSRAN_MAX_CODEWORDS; i++){
    ul_grant->n_prb[i] = ran_ul_grant->n_prb[i];
    ul_grant->n_prb_tilde[i] = ran_ul_grant->n_prb_tilde[i];
  }
  ul_grant->L_prb = ran_ul_grant->L_prb;
  ul_grant->M_sc = ul_grant->L_prb*SRSRAN_NRE;
  ul_grant->M_sc_init = ul_grant->M_sc; // FIXME: What should M_sc_init be?
  ul_grant->Qm = srsran_mod_bits_x_symbol(ul_grant->mcs.mod);
  ul_grant->mcs.mod = ran_ul_grant->tb.mod;
  ul_grant->mcs.idx = ran_ul_grant->tb.mcs_idx;
  ul_grant->mcs.tbs = ran_ul_grant->tb.tbs;
  ul_grant->ncs_dmrs = ran_ul_grant->n_dmrs;
}

void ul_sniffer_dci_rar_unpack(uint8_t payload[SRSRAN_RAR_GRANT_LEN], srsran_dci_rar_grant_t* rar)
{
  uint8_t* ptr      = payload;
  rar->hopping_flag = srsran_bit_pack(&ptr, 1) ? true : false;
  rar->rba          = srsran_bit_pack(&ptr, 10);
  rar->trunc_mcs    = srsran_bit_pack(&ptr, 4);
  rar->tpc_pusch    = srsran_bit_pack(&ptr, 3);
  rar->ul_delay     = srsran_bit_pack(&ptr, 1) ? true : false;
  rar->cqi_request  = srsran_bit_pack(&ptr, 1) ? true : false;
}


int ul_sniffer_dci_rar_to_ul_dci(srsran_cell_t* cell, srsran_dci_rar_grant_t* rar, srsran_dci_ul_t* dci_ul)
{
  bzero(dci_ul, sizeof(srsran_dci_ul_t));

  if (!rar->hopping_flag) {
    dci_ul->freq_hop_fl = SRSRAN_RA_PUSCH_HOP_DISABLED;
  } else {
    ERROR("TODO: Frequency hopping in RAR not implemented");
    dci_ul->freq_hop_fl = 1;
  }
  uint32_t riv = rar->rba;
  // Truncate resource block assignment
  // uint32_t b = 0;
  // if (cell->nof_prb <= 44) {
  //   b   = (uint32_t)(ceilf(log2((float)cell->nof_prb * (cell->nof_prb + 1) / 2)));
  //   riv = riv & ((1 << (b + 1)) - 1);
  // }
  dci_ul->type2_alloc.riv = riv;
  dci_ul->tb.mcs_idx      = rar->trunc_mcs;
  dci_ul->tb.rv           = 0; //-1 orin
  dci_ul->dai             = 3;

  return SRSRAN_SUCCESS;
}
