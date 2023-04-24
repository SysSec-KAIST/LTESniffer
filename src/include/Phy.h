#pragma once

#include <stdint.h>
#include <stdio.h>
#include <memory>

#include "PhyCommon.h"
#include "MetaFormats.h"
#include "WorkerThread.h"
#include "SubframeWorker.h"
#include "include/ThreadSafeQueue.h"
#include "PcapWriter.h"
#include "MCSTracking.h"
#include "ULSchedule.h"
#include "srsran/common/common.h"
#include <future>

#define FALCON_MAX_PRB 110
#define MAX_WORKER_BUFFER 20

//Phy main object
class Phy {
public:
  Phy(uint32_t nof_rx_antennas,
      uint32_t nof_workers,
      const std::string& dciFilenName,
      const std::string& statsFileName,
      bool skipSecondaryMetaFormats,
      double metaFormatSplitRatio,
      uint32_t histogramThreshold,
      LTESniffer_pcap_writer *pcapwriter,
      MCSTracking *mcs_tracking, 
      HARQ *harq,
      int mcs_tracking_mode,
      int harq_mode,
      ULSchedule *ulsche);
  ~Phy();
  std::shared_ptr<SubframeWorker> getAvail();
  std::shared_ptr<SubframeWorker> getAvailImmediate();
  void putAvail(std::shared_ptr<SubframeWorker>);
  std::shared_ptr<SubframeWorker> getPending();
  void putPending(std::shared_ptr<SubframeWorker>);
  void joinPending();
  PhyCommon& getCommon();
  DCIMetaFormats& getMetaFormats();
  std::vector<std::shared_ptr<SubframeWorker> >& getWorkers();
  bool setCell(srsran_cell_t cell);
  void setRNTI(uint16_t rnti);
  void setChestCFOEstimateEnable(bool enable, uint32_t mask);
  void setChestAverageSubframe(bool enable);

  void printStats();

  uint32_t nof_rx_antennas;
  uint32_t nof_workers;
private:
  PhyCommon common;
  DCIMetaFormats metaFormats;

  std::vector<std::shared_ptr<SubframeWorker>> workers;
  ThreadSafeQueue<SubframeWorker> avail;
  ThreadSafeQueue<SubframeWorker> pending;
  std::vector<std::shared_ptr<std::future<void>>>    thread_return;
  std::vector<std::shared_ptr<SnifferThread>>        sniffer_thread;
  std::vector<std::shared_ptr<SubframeWorkerThread>> worker_thread;
};
