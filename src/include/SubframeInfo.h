#pragma once

#include "include/SubframePower.h"
#include "include/DCICollection.h"
#include "ULSchedule.h"
#include "MCSTracking.h"
#include "HARQ.h"

class SubframeInfo {
public:
    SubframeInfo(const srsran_cell_t& cell, 
                 int mcs_tracking_mode, 
                 MCSTracking *mcs_tracking,
                 int harq_mode,
                 HARQ *harq,
                 ULSchedule *ulsche);

    ~SubframeInfo();
    SubframePower& getSubframePower() { return subframePower; }
    const SubframePower& getSubframePower() const { return subframePower; }
    DCICollection& getDCICollection() { return dciCollection; }
    const DCICollection& getDCICollection() const { return dciCollection; }
private:
    SubframePower subframePower;
    DCICollection dciCollection;
};
