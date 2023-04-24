#pragma once

#include "falcon/phy/falcon_ue/falcon_ue_dl.h"
#include "include/SubframeInfo.h"
#include "PhyCommon.h"
#include "MetaFormats.h"
#include "falcon/prof/Lifetime.h"
class DCISearch {
public:
    DCISearch(falcon_ue_dl_t& ue_dl,
              const DCIMetaFormats& metaFormats,
              RNTIManager& rntiManager,
              SubframeInfo& subframeInfo,
              uint32_t sf_idx,
              uint32_t sfn,
              srsran_dl_sf_cfg_t *sf,
              srsran_ue_dl_cfg_t *ue_dl_cfg);

    int search();
    DCIBlindSearchStats& getStats();

    void setShortcutDiscovery(bool enable);
    bool getShortcutDiscovery() const;
    
    /*set nof_antenna = 1 as using antenna 0 for downlink, 1 for uplink */
    void prepareDCISearch();
private:
    int inspect_dci_location_recursively(srsran_dci_msg_t *dci_msg,
                                         uint32_t cfi,
                                         falcon_cce_to_dci_location_map_t *cce_map,
                                         falcon_dci_location_t *location_list,
                                         uint32_t ncce,
                                         uint32_t L,
                                         uint32_t max_depth,
                                         falcon_dci_meta_format_t **meta_formats,
                                         uint32_t nof_formats,
                                         uint32_t enable_discovery,
                                         const dci_candidate_t parent_cand[]);
    int recursive_blind_dci_search(srsran_dci_msg_t *dci_msg,
                                   uint32_t cfi);
    falcon_ue_dl_t& falcon_ue_dl;
    srsran_dl_sf_cfg_t *sf;
    srsran_ue_dl_cfg_t *ue_dl_cfg;
    const DCIMetaFormats& metaFormats;
    RNTIManager& rntiManager;
    DCICollection& dciCollection;
    SubframePower& subframePower;
    uint32_t sf_idx;
    uint32_t sfn;
    DCIBlindSearchStats stats;
    bool enableShortcutDiscovery;
};
