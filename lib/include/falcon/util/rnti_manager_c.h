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

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#include "srsran/phy/phch/dci.h"

typedef enum ActivationReason {
  RM_ACT_UNSET = 0,
  RM_ACT_EVERGREEN,
  RM_ACT_RAR,
  RM_ACT_SHORTCUT,
  RM_ACT_HISTOGRAM,
  RM_ACT_OTHER
} rnti_manager_activation_reason_t;

typedef struct {
  uint16_t rnti;
  uint32_t frequency;
  uint32_t assoc_format_idx;
  rnti_manager_activation_reason_t reason;
  uint32_t last_seen;
} rnti_manager_active_set_t;

void* rnti_manager_create(uint32_t n_formats, uint32_t maxCandidatesPerStepPerFormat, uint32_t histogramThreshold);
void rnti_manager_free(void* h);
void rnti_manager_add_evergreen(void* h, uint16_t rnti_start, uint16_t rnti_end, uint32_t format_idx);
void rnti_manager_add_forbidden(void* h, uint16_t rnti_start, uint16_t rnti_end, uint32_t format_idx);
void rnti_manager_add_candidate(void* h, uint16_t rnti, uint32_t format_idx);
int rnti_manager_validate(void* h, uint16_t rnti, uint32_t format_idx);
int rnti_manager_validate_and_refresh(void* h, uint16_t rnti, uint32_t format_idx);
void rnti_manager_activate_and_refresh(void* h, uint16_t rnti, uint32_t format_idx, rnti_manager_activation_reason_t reason);
int rnti_manager_is_evergreen(void* h, uint16_t rnti, uint32_t format_idx);
int rnti_manager_is_forbidden(void* h, uint16_t rnti, uint32_t format_idx);
void rnti_manager_step_time(void* h);
void rnti_manager_step_time_multi(void* h, uint32_t n_steps);
uint32_t rnti_manager_getFrequency(void* h, uint16_t rnti, uint32_t format_idx);
uint32_t rnti_manager_get_associated_format_idx(void* h, uint16_t rnti);
rnti_manager_activation_reason_t rnti_manager_get_activation_reason(void* h, uint16_t rnti);
void rnti_manager_get_histogram_summary(void* h, uint32_t* buf);
uint32_t rnti_manager_get_active_set(void* h, rnti_manager_active_set_t* buf, uint32_t buf_sz);
void rnti_manager_print_active_set(void* h);

const char* rnti_manager_activation_reason_string(rnti_manager_activation_reason_t reason);

#ifdef __cplusplus
}
#endif
