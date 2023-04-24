#include "include/SubframeInfo.h"

SubframeInfo::SubframeInfo(const srsran_cell_t& cell,
                           int mcs_tracking_mode,
                           MCSTracking *mcs_tracking,
                           int harq_mode, 
                           HARQ *harq,
                           ULSchedule *ulsche):
  subframePower(cell),
  dciCollection(cell, mcs_tracking_mode, mcs_tracking, harq_mode, harq, ulsche)
{

}

SubframeInfo::~SubframeInfo() {

}
