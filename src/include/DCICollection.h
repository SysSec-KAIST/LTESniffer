#pragma once

#include "MCSTracking.h"
#include "HARQ.h"
#include "ULSchedule.h"
#include "include/Sniffer_dependency.h"
#include "falcon/phy/falcon_ue/falcon_ue_dl.h"
#include <vector>
#include <memory>
#include <string>

// include C-only headers
#ifdef __cplusplus
	extern "C" {
#endif

#include "srsran/phy/phch/dci.h"

#ifdef __cplusplus
}
#undef I // Fix complex.h #define I nastiness when using C++
#endif


#define EXPECTED_NOF_DL_DCI_PER_SUBFRAME 10
#define EXPECTED_NOF_UL_DCI_PER_SUBFRAME 10
#define MAX_NOF_DL_PRB 100
#define MAX_NOF_UL_PRB 100

//pre-define from include file
class ULSchedule;

/**
 * @brief The DCICollection class is a container for buffering DCI of a subframe
 */
class DCICollection {

public:
	DCICollection(const srsran_cell_t&  cell,
				  int                   mcs_tracking_mode,
				  MCSTracking           *mcs_tracking,
				  int                   harq_mode,
				  HARQ                  *harq,
				  ULSchedule            *ulsche);
	~DCICollection();
	void setTimestamp(struct timeval timestamp);
	timeval getTimestamp() const;
	void setSubframe(uint32_t sfn, uint32_t sf_idx, uint32_t cfi);
	uint32_t get_sfn() const;
	uint32_t get_sf_idx() const;
	uint32_t get_cfi() const;
	const std::vector<DCI_DL>& getDCI_DL() const;
	const std::vector<DCI_UL>& getDCI_UL() const;
	std::vector<DL_Sniffer_DCI_DL>& getDLSnifferDCI_DL();
	std::vector<DCI_UL>& getULSnifferDCI_UL();
	const std::vector<uint16_t>& getRBMapDL() const;
	const std::vector<uint16_t>& getRBMapUL() const;
	bool hasCollisionDL() const;
	bool hasCollisionUL() const;
	void addCandidate(  dci_candidate_t& cand,
						const srsran_dci_location_t& location,
						uint32_t histval,
						srsran_dl_sf_cfg_t* sf,
						srsran_dci_cfg_t*   cfg);
	static std::vector<uint16_t> applyLegacyColorMap(const std::vector<uint16_t>& RBMap);
	void set_sniffer_mode(int sniffer_mode_){sniffer_mode = sniffer_mode_;}
private:
	int sniffer_mode = DL_MODE;
	srsran_cell_t cell;
	uint32_t sfn;
	uint32_t sf_idx;
	uint32_t cfi;
	struct timeval timestamp;
	std::vector<DCI_DL> dci_dl_collection;
	std::vector<DCI_UL> dci_ul_collection;
	std::vector<DL_Sniffer_DCI_DL> ran_dl_collection;
	std::vector<uint16_t> rb_map_dl;
	std::vector<uint16_t> rb_map_ul;
	bool dl_collision;
	bool ul_collision;
	int mcs_tracking_mode;
	MCSTracking *mcs_tracking;
	ULSchedule  *ulsche;
	int harq_mode;
	HARQ *harq;
};
