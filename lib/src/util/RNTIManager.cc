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
#include <iomanip>
#include <iostream>

#include "falcon/util/RNTIManager.h"

using namespace std;

//////////////////////////////////////////////
/// C wrapper functions for legacy support
//////////////////////////////////////////////

void* rnti_manager_create(uint32_t n_formats, uint32_t maxCandidatesPerStepPerFormat, uint32_t histogramThreshold) {
  return new RNTIManager(n_formats, maxCandidatesPerStepPerFormat, histogramThreshold);
}

void rnti_manager_free(void* h) {
  if(h) {
    RNTIManager* manager = static_cast<RNTIManager*>(h);
    delete manager;
  }
}

void rnti_manager_add_evergreen(void* h, uint16_t rnti_start, uint16_t rnti_end, uint32_t format_idx) {
  if(h) static_cast<RNTIManager*>(h)->addEvergreen(rnti_start, rnti_end, format_idx);
}

void rnti_manager_add_forbidden(void* h, uint16_t rnti_start, uint16_t rnti_end, uint32_t format_idx) {
  if(h) static_cast<RNTIManager*>(h)->addForbidden(rnti_start, rnti_end, format_idx);
}

void rnti_manager_add_candidate(void* h, uint16_t rnti, uint32_t format_idx) {
  if(h) static_cast<RNTIManager*>(h)->addCandidate(rnti, format_idx);
}

int rnti_manager_validate(void* h, uint16_t rnti, uint32_t format_idx) {
  if(h) return static_cast<RNTIManager*>(h)->validate(rnti,format_idx);
  return 0;
}

int rnti_manager_validate_and_refresh(void* h, uint16_t rnti, uint32_t format_idx) {
  if(h) return static_cast<RNTIManager*>(h)->validateAndRefresh(rnti, format_idx);
  return 0;
}

void rnti_manager_activate_and_refresh(void* h, uint16_t rnti, uint32_t format_idx, rnti_manager_activation_reason_t reason) {
  if(h) static_cast<RNTIManager*>(h)->activateAndRefresh(rnti, format_idx, reason);
}

int rnti_manager_is_evergreen(void* h, uint16_t rnti, uint32_t format_idx) {
  if(h) return static_cast<RNTIManager*>(h)->isEvergreen(rnti, format_idx);
  return 0;
}

int rnti_manager_is_forbidden(void* h, uint16_t rnti, uint32_t format_idx) {
  if(h) return static_cast<RNTIManager*>(h)->isForbidden(rnti, format_idx);
  return 0;
}

void rnti_manager_step_time(void* h) {
  if(h) static_cast<RNTIManager*>(h)->stepTime();
}

void rnti_manager_step_time_multi(void* h, uint32_t n_steps) {
  if(h) static_cast<RNTIManager*>(h)->stepTime(n_steps);
}

uint32_t rnti_manager_getFrequency(void* h, uint16_t rnti, uint32_t format_idx) {
  if(h) return static_cast<RNTIManager*>(h)->getFrequency(rnti, format_idx);
  return 0;
}

uint32_t rnti_manager_get_associated_format_idx(void* h, uint16_t rnti) {
  if(h) return static_cast<RNTIManager*>(h)->getAssociatedFormatIdx(rnti);
  return 0;
}

rnti_manager_activation_reason_t rnti_manager_get_activation_reason(void* h, uint16_t rnti) {
  if(h) return static_cast<RNTIManager*>(h)->getActivationReason(rnti);
  return RM_ACT_UNSET;
}

void rnti_manager_get_histogram_summary(void* h, uint32_t* buf) {
  if(h) static_cast<RNTIManager*>(h)->getHistogramSummary(buf);
}

uint32_t rnti_manager_get_active_set(void* h, rnti_manager_active_set_t* buf, uint32_t buf_sz) {
  uint32_t i = 0;
  if(h) {
    RNTIManager* rm = static_cast<RNTIManager*>(h);
    std::vector<rnti_manager_active_set_t> activeSet = rm->getActiveSet();
    while(i < activeSet.size() && i < buf_sz) {
      buf[i] = activeSet[i];
      i++;
    }
  }
  return i;
}

void rnti_manager_print_active_set(void* h) {
  if(h) static_cast<RNTIManager*>(h)->printActiveSet();
}

const char* rnti_manager_activation_reason_string(rnti_manager_activation_reason_t reason) {
  return RNTIManager::getActivationReasonString(reason).c_str();
}

////////////////////////
/// C++ class functions
////////////////////////

RNTIManager::RNTIManager(uint32_t nformats, uint32_t maxCandidatesPerStepPerFormat, uint32_t histogramThreshold) :
  nformats(nformats),
  histograms(nformats, Histogram(RNTI_HISTORY_DEPTH, RNTI_HISTOGRAM_ELEMENT_COUNT)),
  evergreen(nformats, vector<Interval>()),
  forbidden(nformats, vector<Interval>()),
  active(RNTI_HISTOGRAM_ELEMENT_COUNT, false),
  activeSet(),
  lastSeen(RNTI_HISTOGRAM_ELEMENT_COUNT, 0),
  assocFormatIdx(RNTI_HISTOGRAM_ELEMENT_COUNT, 0),
  timestamp(0),
  lifetime(RRC_INACTIVITY_TIMER_MS),
  threshold(histogramThreshold),
  maxCandidatesPerStepPerFormat(maxCandidatesPerStepPerFormat),
  remainingCandidates(nformats, static_cast<int32_t>(maxCandidatesPerStepPerFormat))
{

}

RNTIManager::~RNTIManager() {

}

void RNTIManager::addEvergreen(uint16_t rntiStart, uint16_t rntiEnd, uint32_t formatIdx) {
  evergreen[formatIdx].push_back(Interval(rntiStart, rntiEnd));
}

void RNTIManager::addForbidden(uint16_t rntiStart, uint16_t rntiEnd, uint32_t formatIdx) {
  forbidden[formatIdx].push_back(Interval(rntiStart, rntiEnd));
}

void RNTIManager::addCandidate(uint16_t rnti, uint32_t formatIdx) {
  std::unique_lock<std::mutex> rntiManagerLock(rntiManagerMutex);
  histograms[formatIdx].add(rnti);
  remainingCandidates[formatIdx]--;
}

bool RNTIManager::validate(uint16_t rnti, uint32_t formatIdx) {
  // evergreen consultation
  if(isEvergreen(rnti, formatIdx)) {
    return true;
  }

  if(isForbidden(rnti, formatIdx)) {
      return false;
  }

  // active-list consultation
  RMValidationResult_t rmvRet;
  rmvRet = validateByActiveList(rnti, formatIdx);
  switch (rmvRet) {
    case RMV_TRUE:
      return true;
    case RMV_FALSE:
      return false;
    case RMV_UNCERTAIN:
      // continue validation
      break;
  }

  bool ret;
  ret = validateByHistogram(rnti, formatIdx);
  return ret;
}

bool RNTIManager::validateAndRefresh(uint16_t rnti, uint32_t formatIdx) {
  bool result = validate(rnti, formatIdx);
  if(result) {
    std::unique_lock<std::mutex> rntiManagerLock(rntiManagerMutex);
    lastSeen[rnti] = timestamp;
    rntiManagerLock.unlock();
  }
  return result;
}

void RNTIManager::activateAndRefresh(uint16_t rnti, uint32_t formatIdx, ActivationReason reason) {
  activateRNTI(rnti, reason);
  std::unique_lock<std::mutex> rntiManagerLock(rntiManagerMutex);
  lastSeen[rnti] = timestamp;
  assocFormatIdx[rnti] = formatIdx;
  rntiManagerLock.unlock();
}

uint32_t RNTIManager::getFrequency(uint16_t rnti, uint32_t formatIdx) {
  return histograms[formatIdx].getFrequency(rnti);
}

uint32_t RNTIManager::getAssociatedFormatIdx(uint16_t rnti) {
  return assocFormatIdx[rnti];
}

ActivationReason RNTIManager::getActivationReason(uint16_t rnti) {
  std::unique_lock<std::mutex> rntiManagerLock(rntiManagerMutex);
  for(list<RNTIActiveSetItem>::iterator it = activeSet.begin(); it != activeSet.end(); it++) {
    if(it->rnti == rnti) return it->reason;
  }
  return RM_ACT_UNSET;
}

vector<rnti_manager_active_set_t> RNTIManager::getActiveSet() {
  std::unique_lock<std::mutex> rntiManagerLock(rntiManagerMutex);
  cleanExpired();
  vector<rnti_manager_active_set_t> result(activeSet.size());
  uint32_t index = 0;
  for(list<RNTIActiveSetItem>::iterator it = activeSet.begin(); it != activeSet.end(); it++) {
    result[index].rnti = it->rnti;
    result[index].reason = it->reason;
    result[index].last_seen = timestamp - lastSeen[it->rnti];
    result[index].assoc_format_idx = getAssociatedFormatIdx(it->rnti);
    result[index].frequency = getFrequency(result[index].rnti, result[index].assoc_format_idx);
    if(result[index].assoc_format_idx != 0) {
      result[index].frequency += getFrequency(result[index].rnti, 0);
    }
    index++;
  }
  return result;
}

void RNTIManager::printActiveSet() {
  std::vector<rnti_manager_active_set_t> activeSet = getActiveSet();
  std::vector<rnti_manager_active_set_t>::size_type n_active = activeSet.size();

  std::cout << "----------------------Active RNTI Set----------------------" << std::endl;
  std::cout << "RNTI\tFormat\tFreq\tLast[ms]\tFound by" << std::endl;
  std::cout << "-----------------------------------------------------------" << std::endl;
  for(uint32_t i = 0; i< n_active; i++) {
    std::cout << std::setw(5) << activeSet[i].rnti << "\t";
    std::cout << std::setw(3) << activeSet[i].assoc_format_idx << "\t";
    std::cout << std::setw(4) << activeSet[i].frequency << "\t";
    std::cout << std::setw(7) << activeSet[i].last_seen << "\t";
    std::cout << RNTIManager::getActivationReasonString(activeSet[i].reason) << std::endl;
  }
  std::cout << "-----------------------------------------------------------" << std::endl;
  std::cout << "Total: " << n_active << std::endl;
  std::cout << "-----------------------------------------------------------" << std::endl;

}

string RNTIManager::getActivationReasonString(ActivationReason reason) {
  switch(reason) {
    case RM_ACT_UNSET:
      return "unset";
    case RM_ACT_EVERGREEN:
      return "evergreen";
    case RM_ACT_RAR:
      return "random access";
    case RM_ACT_SHORTCUT:
      return "shortcut";
    case RM_ACT_HISTOGRAM:
      return "histogram";
    case RM_ACT_OTHER:
      return "other";
  }
  return "INVALID";
}

void RNTIManager::getHistogramSummary(uint32_t *buf)
{
  memset(buf, 0, RNTI_HISTOGRAM_ELEMENT_COUNT*sizeof(uint32_t));
  for(uint32_t i=0; i<nformats; i++) {
    const uint32_t* histData = histograms[i].getFrequencyAll();
    for(uint32_t j=0; j<RNTI_HISTOGRAM_ELEMENT_COUNT; j++) {
      buf[j] += histData[j];
    }
  }
}

bool RNTIManager::isEvergreen(uint16_t rnti, uint32_t formatIdx) {
  std::unique_lock<std::mutex> rntiManagerLock(rntiManagerMutex);
  const vector<Interval>& intervals = evergreen[formatIdx];
  for(vector<Interval>::const_iterator inter = intervals.begin(); inter != intervals.end(); inter++) {
    if(inter->matches(rnti)) return true;
  }
  return false;
}

bool RNTIManager::isForbidden(uint16_t rnti, uint32_t formatIdx)  {
  std::unique_lock<std::mutex> rntiManagerLock(rntiManagerMutex);
  const vector<Interval>& intervals = forbidden[formatIdx];
  for(vector<Interval>::const_iterator inter = intervals.begin(); inter != intervals.end(); inter++) {
    if(inter->matches(rnti)) return true;
  }
  return false;
}

RMValidationResult_t RNTIManager::validateByActiveList(uint16_t rnti, uint32_t formatIdx) {
  std::unique_lock<std::mutex> rntiManagerLock(rntiManagerMutex);
  if(active[rnti]) {  // active RNTI
    if(!isExpired(rnti)) {   // lifetime check
      return RMV_TRUE;
      // if(formatIdx == FORMAT_INDEX_UPLINK) return RMV_TRUE; // always accept uplink

      // if(assocFormatIdx[rnti] != ASSOC_FORMAT_INDEX_UNCERTAIN) {  // downlink format locked?
      //   if(assocFormatIdx[rnti] == formatIdx) {
      //     // active + locked + match
      //     return RMV_TRUE;
      //   }
      //   else {
      //     // active + locked, but format mismatch
      //     // format might have changed (e.g. a TM allows two different DCI formats)
      //     return RMV_UNCERTAIN;
      //   }
      // }
      // active but format is uncertain
    }
    else {
      // lifetime expired
      deactivateRNTI(rnti);
    }
  }
  return RMV_UNCERTAIN;
}

bool RNTIManager::validateByHistogram(uint16_t rnti, uint32_t formatIdx) {

  uint32_t likelyDlFormatIdx = getLikelyDlFormatIdx(rnti);
  if(formatIdx != FORMAT_INDEX_UPLINK && formatIdx != likelyDlFormatIdx) {
    // given format is downlink, but not in the most likely dl format - reject!
    // (this also prevents activation of forbidden/evergreen rnti)
    return false;
  }

  uint32_t ulFreq = histograms[FORMAT_INDEX_UPLINK].getFrequency(rnti);
  uint32_t dlFreq = likelyDlFormatIdx != ASSOC_FORMAT_INDEX_UNCERTAIN ? histograms[likelyDlFormatIdx].getFrequency(rnti) : 0;
  if(ulFreq + dlFreq > threshold) {   // exceeds threshold?
    activateRNTI(rnti, RM_ACT_HISTOGRAM);
    if(dlFreq > threshold) {    // dl format certain?
      // lock dl format
      assocFormatIdx[rnti] = likelyDlFormatIdx;
    }
    else {
      // dl format is still uncertain
      assocFormatIdx[rnti] = ASSOC_FORMAT_INDEX_UNCERTAIN;
    }
    return true;  // accept
  }

  // too low frequency - reject!
  return false;
}

uint32_t RNTIManager::getLikelyDlFormatIdx(uint16_t rnti) {
  uint32_t result = ASSOC_FORMAT_INDEX_UNCERTAIN;
  uint32_t maxFreq = 0;
  uint32_t curFreq = 0;
  // start here from formatIdx 1 (FORMAT_INDEX_FIRST_DOWNLINK), skip uplink
  for(uint32_t formatIdx=FORMAT_INDEX_FIRST_DOWNLINK; formatIdx<nformats; formatIdx++) {
    curFreq = histograms[formatIdx].getFrequency(rnti);
    if(curFreq > maxFreq) {
      maxFreq = curFreq;
      result = formatIdx;
    }
  }
  return result;
}

void RNTIManager::activateRNTI(uint16_t rnti, ActivationReason reason) {
  std::unique_lock<std::mutex> rntiManagerLock(rntiManagerMutex);
  if(!active[rnti]) {
    active[rnti] = true;
    activeSet.push_back(RNTIActiveSetItem(rnti, reason));
  }
}

void RNTIManager::deactivateRNTI(uint16_t rnti) {
  if(active[rnti]) {
    active[rnti] = false;
    assocFormatIdx[rnti] = 0;
    activeSet.remove(RNTIActiveSetItem(rnti));
  }
}

bool RNTIManager::isExpired(uint16_t rnti) {
  bool result = true;
  if(active[rnti]) {
    if(timestamp - lastSeen[rnti] < lifetime) {
      result = false;
    }
  }
  return result;
}

void RNTIManager::cleanExpired() {
  std::unique_lock<std::mutex> rntiManagerLock(rntiManagerMutex);
  list<RNTIActiveSetItem>::iterator it = activeSet.begin();
  while(it != activeSet.end()) {
    if(isExpired(it->rnti)) {
      it = activeSet.erase(it);
    }
    else {
      ++it;
    }
  }
}

void RNTIManager::stepTime() {
  // add padding to histograms
  for(uint32_t i=0; i<nformats; i++) {
    if(remainingCandidates[i] > 0) {
      histograms[i].add(ILLEGAL_RNTI, static_cast<uint32_t>(remainingCandidates[i]));
    }
    remainingCandidates[i] = static_cast<int32_t>(maxCandidatesPerStepPerFormat); // reset
  }
  timestamp++;
}

void RNTIManager::stepTime(uint32_t nSteps) {
  for(uint32_t i=0; i<nSteps; i++) {
    stepTime();
  }
}

void RNTIManager::setHistogramThreshold(uint32_t threshold) {
  this->threshold = threshold;
}
