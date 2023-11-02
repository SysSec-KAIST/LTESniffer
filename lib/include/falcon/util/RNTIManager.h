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

#include <vector>
#include <list>
#include <string.h>
#include <strings.h>
#include <string>
#include <memory>
#include "mutex"
#include "memory"

#include "falcon/common/Settings.h"
#include "rnti_manager_c.h"

#include "Histogram.h"
#include "Interval.h"

// DCI minimum average llr for accepting DCI for blind decoding
//#define DCI_MINIMUM_AVG_LLR_BOUND 0.5     //0.5

// RRC Inactivity Timer
#define RRC_INACTIVITY_TIMER_MS 10000   // Range 0..60000, default 10000

// RNTI histogram and circular buffer
#define RNTI_HISTOGRAM_ELEMENT_COUNT 65536

#define RNTI_HISTORY_DEPTH_MSEC 200  //200
#define RNTI_PER_SUBFRAME (304/5)
#define RNTI_HISTORY_DEPTH (RNTI_HISTORY_DEPTH_MSEC)*(RNTI_PER_SUBFRAME)

// Reserverd values
#define ILLEGAL_RNTI 0

// Constant values for format indices
#define FORMAT_INDEX_UPLINK 0
#define FORMAT_INDEX_FIRST_DOWNLINK (FORMAT_INDEX_UPLINK + 1)
#define ASSOC_FORMAT_INDEX_UNCERTAIN 0

typedef enum {
  RMV_FALSE = 0,
  RMV_UNCERTAIN = 1,
  RMV_TRUE = 2,
} RMValidationResult_t;

class RNTIActiveSetItem {
public:
  uint16_t rnti;
  ActivationReason reason;
  RNTIActiveSetItem(uint16_t rnti, ActivationReason reason = RM_ACT_UNSET) :
    rnti(rnti),
    reason(reason) {}
  bool operator==(const RNTIActiveSetItem& other) const { return rnti == other.rnti; }
  bool operator!=(const RNTIActiveSetItem& other) const { return rnti != other.rnti; }
};

class RNTIManager {
public:
  RNTIManager(uint32_t nformats, uint32_t maxCandidatesPerStepPerFormat, uint32_t histogramThreshold);
  virtual ~RNTIManager();

  virtual void addEvergreen(uint16_t rntiStart, uint16_t rntiEnd, uint32_t formatIdx);
  virtual void addForbidden(uint16_t rntiStart, uint16_t rntiEnd, uint32_t formatIdx);
  virtual void addCandidate(uint16_t rnti, uint32_t formatIdx);
  virtual bool validate(uint16_t rnti, uint32_t formatIdx);
  virtual bool validateAndRefresh(uint16_t rnti, uint32_t formatIdx);
  virtual void activateAndRefresh(uint16_t rnti, uint32_t formatIdx, ActivationReason reason);
  virtual bool isEvergreen(uint16_t rnti, uint32_t formatIdx) ;
  virtual bool isForbidden(uint16_t rnti, uint32_t formatIdx) ;
  virtual void stepTime();
  virtual void stepTime(uint32_t nSteps);
  virtual void setHistogramThreshold(uint32_t threshold);
  virtual uint32_t getFrequency(uint16_t rnti, uint32_t formatIdx);
  virtual uint32_t getAssociatedFormatIdx(uint16_t rnti);
  virtual ActivationReason getActivationReason(uint16_t rnti);
  virtual void getHistogramSummary(uint32_t* buf);
  virtual std::vector<rnti_manager_active_set_t> getActiveSet();
  virtual void printActiveSet();

  static std::string getActivationReasonString(ActivationReason reason);
private:
  RNTIManager(const RNTIManager&);    // prevent copy
  RMValidationResult_t validateByActiveList(uint16_t rnti, uint32_t formatIdx);
  bool validateByHistogram(uint16_t rnti, uint32_t formatIdx);
  virtual uint32_t getLikelyDlFormatIdx(uint16_t rnti);
  void activateRNTI(uint16_t rnti, ActivationReason reason);
  void deactivateRNTI(uint16_t rnti);
  bool isExpired(uint16_t rnti) ;
  void cleanExpired();
  uint32_t nformats;
  std::vector<Histogram> histograms;
  std::vector<std::vector<Interval> > evergreen;
  std::vector<std::vector<Interval> > forbidden;
  std::vector<bool> active;
  std::list<RNTIActiveSetItem> activeSet;
  std::vector<uint32_t> lastSeen;
  std::vector<uint32_t> assocFormatIdx;
  uint32_t timestamp;
  uint32_t lifetime;
  uint32_t threshold;
  uint32_t maxCandidatesPerStepPerFormat;
  std::vector<int32_t> remainingCandidates;
  std::mutex rntiManagerMutex;
};
