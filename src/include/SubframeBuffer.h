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
#include "srsran/srsran.h"

#define UL_SNIFFER_MAX_NOF_OFFSET 2

struct SubframeBuffer {
  SubframeBuffer(uint32_t rf_nof_rx_ant);
  SubframeBuffer(const SubframeBuffer&) = delete; //prevent copy
  SubframeBuffer& operator=(const SubframeBuffer&) = delete; //prevent copy
  ~SubframeBuffer();
  const uint32_t rf_nof_rx_ant;
  cf_t *sf_buffer[SRSRAN_MAX_PORTS] = {nullptr};
  cf_t *sf_buffer_offset[UL_SNIFFER_MAX_NOF_OFFSET] = {nullptr}; // idx 0 for 32, idx 1 for 64
};
