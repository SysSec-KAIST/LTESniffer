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
#include "include/SubframeBuffer.h"

SubframeBuffer::SubframeBuffer(uint32_t rf_nof_rx_ant) : rf_nof_rx_ant(rf_nof_rx_ant) {
  for (uint32_t i = 0; i < rf_nof_rx_ant; i++) {
    sf_buffer[i] = static_cast<cf_t*>(srsran_vec_malloc(3*static_cast<uint32_t>(sizeof(cf_t))*static_cast<uint32_t>(SRSRAN_SF_LEN_PRB(100))));
  }
  for (uint32_t i = 0; i < UL_SNIFFER_MAX_NOF_OFFSET; i++) {
    sf_buffer_offset[i] = static_cast<cf_t*>(srsran_vec_malloc(3*static_cast<uint32_t>(sizeof(cf_t))*static_cast<uint32_t>(SRSRAN_SF_LEN_PRB(100))));
  }
}

SubframeBuffer::~SubframeBuffer() {
  for (uint32_t i = 0; i < rf_nof_rx_ant; i++) {
    free(sf_buffer[i]);
    sf_buffer[i] = nullptr;
  }
  for (uint32_t i = 0; i < UL_SNIFFER_MAX_NOF_OFFSET; i++) {
    free(sf_buffer_offset[i]);
    sf_buffer_offset[i] = nullptr;
  }
}
