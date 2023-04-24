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
#include <vector>

class Histogram {
public:
  Histogram(uint32_t itemCount, uint32_t valueRange);
  //Histogram(const Histogram& other);
  virtual ~Histogram();
  virtual void add(uint16_t item);
  virtual void add(uint16_t item, uint32_t nTimes);
  virtual uint32_t getFrequency(uint16_t item) const;
  virtual const uint32_t* getFrequencyAll() const;
  virtual bool ready() const;
  virtual uint32_t getItemCount() const;
  virtual uint32_t getValueRange() const;
private:
  //void initBuffers();
  std::vector<uint32_t> rnti_histogram;           // the actual histogram
  std::vector<uint16_t> rnti_history;             // circular buffer of the recent seen RNTIs
  uint32_t rnti_history_current;     // index to current head/(=foot) of rnti_history
  uint32_t rnti_history_end;         // index to highest index in history array
  //int rnti_history_active_users;      // number of currently active RNTIs
  bool rnti_histogram_ready;           // ready-indicator, if history is filled
  uint32_t itemCount;
  uint32_t valueRange;
};
