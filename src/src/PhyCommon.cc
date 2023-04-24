#include "include/PhyCommon.h"
#include <cstdlib>

PhyCommon::PhyCommon(uint32_t max_prb,
                     uint32_t nof_rx_antennas,
                     const std::string& dciFileName,
                     const std::string& statsFileName,
                     uint32_t histogramThreshold) :
  max_prb(max_prb),
  nof_rx_antennas(nof_rx_antennas),
  rntiManager(nof_falcon_ue_all_formats, RNTI_PER_SUBFRAME, histogramThreshold),
  stats(),
  defaultDCIConsumer(new DCIToFile()),
  dciConsumer(defaultDCIConsumer),
  enableShortcutDiscovery(true)
{


  if(dciFileName.length() > 0) {
    dci_file = fopen(dciFileName.c_str(), "w");
  }
  else {
    dci_file = stdout;
  }

  if(statsFileName.length() > 0) {
    stats_file = fopen(statsFileName.c_str(), "w");
  }
  else {
    stats_file = stdout;
  }

  defaultDCIConsumer->setFile(dci_file);
}

PhyCommon::~PhyCommon() {
  if(dci_file != stdout) {
    fclose(dci_file);
  }
  if(stats_file != stdout) {
    fclose(stats_file);
  }
}

RNTIManager& PhyCommon::getRNTIManager() {
  return rntiManager;
}

FILE* PhyCommon::getDCIFile() {
  return dci_file;
}

FILE* PhyCommon::getStatsFile() {
  return stats_file;
}

void PhyCommon::addStats(const DCIBlindSearchStats& stats) {
  this->stats += stats;
}

DCIBlindSearchStats& PhyCommon::getStats() {
  return stats;
}

void PhyCommon::printStats() {
  stats.print(stats_file);
}

void PhyCommon::setShortcutDiscovery(bool enable) {
  enableShortcutDiscovery = enable;
}

bool PhyCommon::getShortcutDiscovery() const {
  return enableShortcutDiscovery;
}

void PhyCommon::setDCIConsumer(std::shared_ptr<SubframeInfoConsumer> consumer) {
  dciConsumer = consumer;
}

void PhyCommon::resetDCIConsumer() {
  dciConsumer = defaultDCIConsumer;
}

void PhyCommon::consumeDCICollection(const SubframeInfo& subframeInfo) {
  // maybe this is a good point for synchronization
  dciConsumer->consumeDCICollection(subframeInfo);
}

DCIBlindSearchStats::DCIBlindSearchStats() {
  nof_cce = 0;
  nof_locations = 0;
  nof_decoded_locations = 0;
  nof_missed_cce = 0;
  nof_subframes = 0;
  nof_subframe_collisions_dw = 0;
  nof_subframe_collisions_up = 0;
  time_blindsearch.tv_sec = 0;
  time_blindsearch.tv_usec = 0;
}

void DCIBlindSearchStats::print(FILE* file) {
  fprintf(file, "nof_decoded_locations, nof_cce, nof_missed_cce, nof_subframes, nof_subframe_collisions_dw, nof_subframe_collisions_up, time, nof_locations\n");
  fprintf(file, "%d, %d, %d, %d, %d, %d, %ld.%06ld, %d\n",
          nof_decoded_locations,
          nof_cce,
          nof_missed_cce,
          nof_subframes,
          nof_subframe_collisions_dw,
          nof_subframe_collisions_up,
          time_blindsearch.tv_sec,
          time_blindsearch.tv_usec,
          nof_locations);
}

DCIBlindSearchStats& DCIBlindSearchStats::operator+=(const DCIBlindSearchStats& right) {
  nof_cce                     += right.nof_cce;
  nof_locations               += right.nof_locations;
  nof_decoded_locations       += right.nof_decoded_locations;
  nof_missed_cce              += right.nof_missed_cce;
  nof_subframes               += right.nof_subframes;
  nof_subframe_collisions_dw  += right.nof_subframe_collisions_dw;
  nof_subframe_collisions_up  += right.nof_subframe_collisions_up;
  time_blindsearch.tv_sec     += right.time_blindsearch.tv_sec;
  time_blindsearch.tv_usec    += right.time_blindsearch.tv_usec;
  return *this;
}

