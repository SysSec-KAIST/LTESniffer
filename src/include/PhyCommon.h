#pragma once

#include <stdint.h>
#include "falcon/util/RNTIManager.h"
#include "falcon/phy/falcon_phch/falcon_dci.h"
#include "SubframeInfoConsumer.h"

extern const srsran_dci_format_t falcon_ue_all_formats[];
extern const uint32_t nof_falcon_ue_all_formats;

class DCIBlindSearchStats {
public:
    DCIBlindSearchStats();
    void print(FILE* file);
    DCIBlindSearchStats& operator+=(const DCIBlindSearchStats& right);

    uint32_t nof_locations;
    uint32_t nof_decoded_locations;
    uint32_t nof_cce;
    uint32_t nof_missed_cce;
    uint32_t nof_subframes;
    uint32_t nof_subframe_collisions_dw;
    uint32_t nof_subframe_collisions_up;
    struct timeval time_blindsearch;
};

class PhyStats {
public:
    PhyStats();
    ~PhyStats();
    PhyStats& operator+=(const PhyStats& right);

    uint32_t totRBup, totRBdw, totBWup, totBWdw;
    uint16_t nof_rnti;
};

class PhyCommon {
public:
  PhyCommon(uint32_t max_prb,
            uint32_t nof_rx_antennas,
            const std::string& dciFileName,
            const std::string& statsFileName,
            uint32_t histogramThreshold);
  ~PhyCommon();
  RNTIManager& getRNTIManager();
  FILE* getDCIFile();
  FILE* getStatsFile();
  void addStats(const DCIBlindSearchStats& stats);
  DCIBlindSearchStats& getStats();
  void printStats();

  void setShortcutDiscovery(bool enable);
  bool getShortcutDiscovery() const;

  //upper layer interfaces
  void setDCIConsumer(std::shared_ptr<SubframeInfoConsumer>);
  void resetDCIConsumer();

  //lower layer interface
  void consumeDCICollection(const SubframeInfo& subframeInfo);

  uint32_t max_prb;
  uint32_t nof_rx_antennas;
private:
  FILE* dci_file;
  FILE* stats_file;
  RNTIManager rntiManager;

  DCIBlindSearchStats stats;

  std::shared_ptr<DCIToFile> defaultDCIConsumer;
  std::shared_ptr<SubframeInfoConsumer> dciConsumer;

  bool enableShortcutDiscovery;
};
