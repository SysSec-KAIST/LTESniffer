#include "include/ULSchedule.h"

ULSchedule::ULSchedule(uint32_t rnti, UL_HARQ *ul_harq, bool en_debug) : rnti(rnti),
																		 en_debug(en_debug)
{
}
ULSchedule::~ULSchedule()
{
}

void ULSchedule::pushULSche(uint32_t tti, const std::vector<DCI_UL> &dci_ul)
{
	std::unique_lock<std::mutex> lock(ulsche_mutex);
	/* Check if there is UL_DCI for this tti in the database*/
	std::map<uint32_t, std::vector<DCI_UL>>::iterator iter;
	iter = ulsche_database.find(tti);
	if (iter != ulsche_database.end())
	{
		iter->second.insert((*iter).second.end(), dci_ul.begin(), dci_ul.end());
	}
	else
	{ // if not create a new one
		ulsche_database.insert(std::pair<uint32_t, std::vector<DCI_UL>>(tti, dci_ul));
	}
	lock.unlock();
}

void ULSchedule::push_rar_ULSche(uint32_t tti, const std::vector<DCI_UL> &rar_dci_ul)
{
	std::unique_lock<std::mutex> lock(ulsche_mutex);
	// std::vector<DCI_UL> cur_dci_ul;
	// cur_dci_ul = rar_dci_ul;
	ulsche_rar_database.insert(std::pair<uint32_t, std::vector<DCI_UL>>(tti, rar_dci_ul));
	lock.unlock();
}

std::vector<DCI_UL> *ULSchedule::getULSche(uint32_t tti)
{
	std::unique_lock<std::mutex> lock(ulsche_mutex);
	uint32_t ul_tti = get_ul_tti(tti);
	std::map<uint32_t, std::vector<DCI_UL>>::iterator iter;
	iter = ulsche_database.find(ul_tti);
	if (iter != ulsche_database.end())
	{
		return &iter->second;
	}
	else
	{
		return nullptr;
	}
	lock.unlock();
}

std::vector<DCI_UL> *ULSchedule::get_rar_ULSche(uint32_t tti)
{
	std::unique_lock<std::mutex> lock(ulsche_mutex);
	uint32_t ul_tti = get_rar_ul_tti(tti);
	std::map<uint32_t, std::vector<DCI_UL>>::iterator iter;
	iter = ulsche_rar_database.find(ul_tti);
	if (iter != ulsche_rar_database.end())
	{
		return &iter->second;
	}
	else
	{
		return nullptr;
	}
	lock.unlock();
}

void ULSchedule::deleteULSche(uint32_t tti)
{
	std::unique_lock<std::mutex> lock(ulsche_mutex);
	std::map<uint32_t, std::vector<DCI_UL>>::iterator iter;
	uint32_t ul_tti = get_ul_tti(tti);
	iter = ulsche_database.find(ul_tti);
	if (iter != ulsche_database.end())
	{
		ulsche_database.erase(iter);
	}
	else
	{
		// do nothing
	}
	lock.unlock();
}

void ULSchedule::delete_rar_ULSche(uint32_t tti)
{
	std::unique_lock<std::mutex> lock(ulsche_mutex);
	std::map<uint32_t, std::vector<DCI_UL>>::iterator iter;
	uint32_t ul_tti = get_rar_ul_tti(tti);
	iter = ulsche_rar_database.find(ul_tti);
	if (iter != ulsche_rar_database.end())
	{
		ulsche_rar_database.erase(iter);
	}
	else
	{
		// do nothing
	}
	lock.unlock();
}

void ULSchedule::set_SIB2(asn1::rrc::sib_type2_s *sib2_)
{
	std::unique_lock<std::mutex> lock(ulsche_mutex);
	sib2 = *sib2_;
	lock.unlock();
}

int ULSchedule::get_ul_tti(uint32_t cur_tti)
{
	int temp_tti = (int)cur_tti - 4;
	if (temp_tti >= 0)
	{
		return temp_tti;
	}
	else
	{
		temp_tti = temp_tti + 10240;
		return temp_tti;
	}
}

int ULSchedule::get_rar_ul_tti(uint32_t cur_tti)
{
	int temp_tti = (int)cur_tti - 6;
	if (temp_tti >= 0)
	{
		return temp_tti;
	}
	else
	{
		temp_tti = temp_tti + 10240;
		return temp_tti;
	}
}

void ULSchedule::set_config()
{
	std::unique_lock<std::mutex> lock(ulsche_mutex);
	dmrs_cfg.cyclic_shift = sib2.rr_cfg_common.pusch_cfg_common.ul_ref_sigs_pusch.cyclic_shift;
	dmrs_cfg.group_hopping_en = sib2.rr_cfg_common.pusch_cfg_common.ul_ref_sigs_pusch.group_hop_enabled;
	dmrs_cfg.sequence_hopping_en = sib2.rr_cfg_common.pusch_cfg_common.ul_ref_sigs_pusch.seq_hop_enabled;
	dmrs_cfg.delta_ss = sib2.rr_cfg_common.pusch_cfg_common.ul_ref_sigs_pusch.group_assign_pusch;

	/*set parch config*/
	prach_cfg.is_nr = false;
	prach_cfg.root_seq_idx = sib2.rr_cfg_common.prach_cfg.root_seq_idx;
	prach_cfg.config_idx = sib2.rr_cfg_common.prach_cfg.prach_cfg_info.prach_cfg_idx;
	prach_cfg.hs_flag = sib2.rr_cfg_common.prach_cfg.prach_cfg_info.high_speed_flag;
	prach_cfg.zero_corr_zone = sib2.rr_cfg_common.prach_cfg.prach_cfg_info.zero_correlation_zone_cfg;
	prach_cfg.freq_offset = sib2.rr_cfg_common.prach_cfg.prach_cfg_info.prach_freq_offset;

	config = true;
	lock.unlock();
}

srsran_refsignal_dmrs_pusch_cfg_t ULSchedule::get_dmrs()
{
	std::unique_lock<std::mutex> lock(ulsche_mutex);
	if (print_get_config)
	{
		// printf("[CONFIG] Configuring DMRS for Subframe Workers \n");
		print_get_config = false;
	}
	return dmrs_cfg;
	lock.unlock();
}

void ULSchedule::clean_database(std::map<uint32_t, UL_Sniffer_arrival_time_t>::iterator iter)
{
	iter->second.arvl_time_database.clear();
	iter->second.arvl_time_failed_database.clear();
	iter->second.arvl_time_h_snr_database.clear();
	iter->second.arvl_time_l_snr_database.clear();
	iter->second.arvl_time_success_database.clear();

	iter->second.avg_database.clear();
	iter->second.avg_failed_database.clear();
	iter->second.avg_h_snr_database.clear();
	iter->second.avg_l_snr_database.clear();
	iter->second.avg_success_database.clear();
}

void ULSchedule::set_rrc_con_set(asn1::rrc::rrc_conn_setup_r8_ies_s rrc_con_set_)
{
	rrc_con_set = rrc_con_set_;
	has_rrc_con_set = true;
}