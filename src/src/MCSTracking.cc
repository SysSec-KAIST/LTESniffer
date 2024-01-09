#include "include/MCSTracking.h"

MCSTracking::MCSTracking(int tracking_mode,
                         uint16_t target_rnti,
                         bool en_debug,
                         int sniffer_mode,
                         int api_mode,
                         std::atomic<float> &est_cfo) : target_rnti(target_rnti),
                                                        tracking_mode(tracking_mode),
                                                        en_debug(en_debug),
                                                        sniffer_mode(sniffer_mode),
                                                        api_mode(api_mode),
                                                        est_cfo(est_cfo)
{
    set_default_of_default_config();
    csv_file.open(file_name);
    csv_file << "RNTI, table, total,success,percent,";
    for (int mcs_idx = 0; mcs_idx < DL_SNIFFER_NOF_MCS; mcs_idx++)
    {
        csv_file << mcs_idx << ',';
    }
    csv_file << "\n";
}

MCSTracking::~MCSTracking()
{
    csv_file.close();
}

/*___________UL 256/64/16QAM tracking implementation__________*/

ul_sniffer_mod_tracking_t MCSTracking::find_tracking_info_RNTI_ul(uint16_t RNTI)
{

    std::unique_lock<std::mutex> trackinglock(tracking_mutex);
    std::map<uint16_t, ul_sniffer_tracking_t>::iterator iter;
    iter = tracking_database_ul_mode.find(RNTI);
    if ((nof_RNTI_member_ul() == 0) || (iter == tracking_database_ul_mode.end()))
    {
        if (nof_RNTI_member_ul() < max_size)
        {
            // add_RNTI(RNTI, UL_SNIFFER_UNKNOWN_MOD);
            return UL_SNIFFER_UNKNOWN_MOD;
        }
        else
        {
            return UL_SNIFFER_FULL_BUFFER;
        }
    }
    else
    {
        clock_t cur_time = clock();
        iter->second.time = cur_time;
        return iter->second.mcs_mod;
    }
    trackinglock.unlock();
}

int MCSTracking::add_RNTI_ul(uint16_t RNTI, ul_sniffer_mod_tracking_t mcs_mod)
{
    clock_t cur_time = clock();
    ul_sniffer_tracking_t new_tracking;
    new_tracking.time = cur_time;
    new_tracking.mcs_mod = mcs_mod;
    new_tracking.ue_spec_config = default_ue_spec_config;
    new_tracking.ue_spec_config.has_ue_config = false;
    tracking_database_ul_mode.insert(std::pair<uint16_t, ul_sniffer_tracking_t>(RNTI, (std::move(new_tracking))));
    return SRSRAN_SUCCESS;
}

void MCSTracking::update_RNTI_ul(uint16_t RNTI, ul_sniffer_mod_tracking_t mcs_mod)
{
    std::unique_lock<std::mutex> trackinglock(tracking_mutex);
    std::map<uint16_t, ul_sniffer_tracking_t>::iterator iter;
    iter = tracking_database_ul_mode.find(RNTI);
    if (iter != tracking_database_ul_mode.end())
    {
        iter->second.mcs_mod = mcs_mod;
    }
    else
    {
        add_RNTI_ul(RNTI, UL_SNIFFER_UNKNOWN_MOD);
    }
    trackinglock.unlock();
}

void MCSTracking::update_database_ul()
{
    std::unique_lock<std::mutex> trackinglock(tracking_mutex);
    std::vector<uint16_t> del_list;
    clock_t cur_time = clock();
    long double cur_interval = 0;
    std::map<uint16_t, ul_sniffer_tracking_t>::iterator iter;
    for (iter = tracking_database_ul_mode.begin(); iter != tracking_database_ul_mode.end(); iter++)
    {
        clock_t last_time = iter->second.time;
        cur_interval = (long double)((cur_time - last_time) / CLOCKS_PER_SEC);
        bool wrong_detect = false; // wrong detection if decode wrong mimo multiple times

        /*Only add to final data base if there was no error when decoding PDSCH and nof_active = 0*/
        if (((iter->second.nof_active == 0)) || (iter->second.nof_active <= 10 && iter->second.nof_success_mgs == 0 &&
                                                 (iter->second.nof_unsupport_mimo > 0 || iter->second.nof_pinfo > 0 || iter->second.nof_other_mimo > 0)))
        {
            wrong_detect = true;
            iter->second.to_all_database = false;
        }
        if (cur_interval > interval || wrong_detect || iter->second.nof_active == 0)
        {
            del_list.push_back(iter->first);
        }
    }
    if (del_list.size() != 0)
    {
        std::vector<uint16_t>::iterator iter;
        std::map<uint16_t, ul_sniffer_tracking_t>::iterator del_iter;
        for (iter = del_list.begin(); iter != del_list.end(); iter++)
        {
            del_iter = tracking_database_ul_mode.find(*iter);
            /*Update RNTI to final database (this database will not be deleted)*/
            if (del_iter->second.to_all_database)
            {
                auto add_iter = all_database_ul_mode.find(*iter);
                if (add_iter != all_database_ul_mode.end())
                {
                    add_iter->second.nof_active += del_iter->second.nof_active;
                    add_iter->second.nof_newtx += del_iter->second.nof_newtx;
                    add_iter->second.nof_success_mgs += del_iter->second.nof_success_mgs;
                    add_iter->second.nof_retx += del_iter->second.nof_retx;
                    add_iter->second.nof_success_retx_nom += del_iter->second.nof_success_retx_nom;
                    add_iter->second.nof_success_retx_harq += del_iter->second.nof_success_retx_harq;
                    add_iter->second.nof_success_retx += del_iter->second.nof_success_retx;
                    add_iter->second.nof_unsupport_mimo += del_iter->second.nof_unsupport_mimo;
                    for (int mcs_idx = 0; mcs_idx < DL_SNIFFER_NOF_MCS; mcs_idx++)
                    {
                        add_iter->second.mcs[mcs_idx] += del_iter->second.mcs[mcs_idx];
                        add_iter->second.mcs_sc[mcs_idx] += del_iter->second.mcs_sc[mcs_idx];
                    }
                    float sum_snr = 0;
                    float ave_snr = 0;
                    if (del_iter->second.snr.size() > 0)
                    {
                        for (float x : del_iter->second.snr)
                        {
                            sum_snr += x;
                        }
                        ave_snr = sum_snr / del_iter->second.snr.size();
                    }
                    add_iter->second.snr.push_back(ave_snr);

                    /*TA*/
                    float sum_ta = 0;
                    float ave_ta = 0;
                    if (del_iter->second.ta.size() > 0)
                    {
                        for (float x : del_iter->second.ta)
                        {
                            sum_ta += x;
                        }
                        ave_ta = sum_ta / del_iter->second.ta.size();
                    }
                    add_iter->second.ta.push_back(ave_ta);
                }
                else
                {
                    ul_sniffer_tracking_t temp_tracking = {};
                    temp_tracking = del_iter->second;
                    uint16_t temp_rnti = del_iter->first;
                    std::pair<uint16_t, ul_sniffer_tracking_t> temp_pair(temp_rnti, temp_tracking);
                    all_database_ul_mode.insert(std::move(temp_pair));
                }
            }
            if (del_iter != tracking_database_ul_mode.end())
            {
                tracking_database_ul_mode.erase(del_iter);
            }
        }
    }
    trackinglock.unlock();
}

void MCSTracking::merge_all_database_ul()
{
    std::unique_lock<std::mutex> trackinglock(tracking_mutex);
    std::map<uint16_t, ul_sniffer_tracking_t>::iterator merge_iter;
    for (merge_iter = tracking_database_ul_mode.begin(); merge_iter != tracking_database_ul_mode.end(); merge_iter++)
    {
        auto add_iter = all_database_ul_mode.find(merge_iter->first);
        if (add_iter != all_database_ul_mode.end())
        {
            add_iter->second.nof_active += merge_iter->second.nof_active;
            add_iter->second.nof_newtx += merge_iter->second.nof_newtx;
            add_iter->second.nof_success_mgs += merge_iter->second.nof_success_mgs;
            add_iter->second.nof_retx += merge_iter->second.nof_retx;
            add_iter->second.nof_success_retx_nom += merge_iter->second.nof_success_retx_nom;
            add_iter->second.nof_success_retx_harq += merge_iter->second.nof_success_retx_harq;
            add_iter->second.nof_success_retx += merge_iter->second.nof_success_retx;
            add_iter->second.nof_unsupport_mimo += merge_iter->second.nof_unsupport_mimo;
            for (int mcs_idx = 0; mcs_idx < DL_SNIFFER_NOF_MCS; mcs_idx++)
            {
                add_iter->second.mcs[mcs_idx] += merge_iter->second.mcs[mcs_idx];
                add_iter->second.mcs_sc[mcs_idx] += merge_iter->second.mcs_sc[mcs_idx];
            }
            float sum_snr = 0;
            float ave_snr = 0;
            if (merge_iter->second.snr.size() > 0)
            {
                for (float x : merge_iter->second.snr)
                {
                    sum_snr += x;
                }
                ave_snr = sum_snr / merge_iter->second.snr.size();
            }
            add_iter->second.snr.push_back(ave_snr);

            /*TA*/
            float sum_ta = 0;
            float ave_ta = 0;
            if (merge_iter->second.ta.size() > 0)
            {
                for (float x : merge_iter->second.ta)
                {
                    sum_ta += x;
                }
                ave_ta = sum_ta / merge_iter->second.ta.size();
            }
            add_iter->second.ta.push_back(ave_ta);
        }
        else
        {
            ul_sniffer_tracking_t temp_tracking = {};
            temp_tracking = merge_iter->second;
            uint16_t temp_rnti = merge_iter->first;
            std::pair<uint16_t, ul_sniffer_tracking_t> temp_pair(temp_rnti, temp_tracking);
            all_database_ul_mode.insert(std::move(temp_pair));
        }
    }

    trackinglock.unlock();
}

void print_statistic_rnti_ul_mode(std::stringstream &msg, std::map<uint16_t, ul_sniffer_tracking_t>::iterator iter, int num, std::string info)
{
    msg << "            ";
    msg << std::left << std::setw(5) << num;
    msg << std::left << std::setw(9) << iter->first;
    msg << std::left << std::setw(12) << info;
    msg << std::left << std::setw(9) << iter->second.nof_active;
    msg << std::left << std::setw(9) << iter->second.nof_success_mgs;
    float sum_snr = 0;
    float ave_snr = 0;
    if (iter->second.snr.size() > 0)
    {
        for (float x : iter->second.snr)
        {
            sum_snr += x;
        }
        ave_snr = sum_snr / iter->second.snr.size();
    }
    msg << std::left << std::setw(9) << std::setprecision(3) << ave_snr;
    // iter->second.snr.clear();
    /*TA*/
    float sum_ta = 0;
    float ave_ta = 0;
    if (iter->second.ta.size() > 0)
    {
        for (float x : iter->second.ta)
        {
            sum_ta += x;
        }
        ave_ta = sum_ta / iter->second.ta.size();
    }
    if (ave_ta >= 0)
    {
        msg << "+";
        msg << std::left << std::setw(17) << std::setprecision(3) << ave_ta;
    }
    else
    {
        msg << std::left << std::setw(18) << std::setprecision(3) << ave_ta;
    }

    msg << std::left << std::setw(9) << iter->second.nof_other_mimo;
    msg << std::endl;
}

void print_header_ul_mode(std::stringstream &msg)
{
    auto now = std::chrono::system_clock::now();
	std::time_t cur_time = std::chrono::system_clock::to_time_t(now);
	std::string str_cur_time(std::ctime(&cur_time));
	std::string cur_time_second;
	if(str_cur_time.length()>=(11+8)){
        cur_time_second = str_cur_time.substr(11,8);
    }else{
        cur_time_second = "";
    }
	msg << "[" << cur_time_second << "]: ";
    
    msg << std::left << std::setw(5) << "Num";
    msg << std::left << std::setw(9) << "RNTI";
    msg << std::left << std::setw(12) << "Max Mod";
    msg << std::left << std::setw(9) << "Active";
    msg << std::left << std::setw(9) << "Success";
    msg << std::left << std::setw(9) << "SNR(dB)";
    msg << std::left << std::setw(18) << "DL-UL_delay(us)";
    msg << std::left << std::setw(9) << "Other_Info";
    msg << std::endl;
}

void MCSTracking::print_database_ul(LTESniffer_stat_writer  *filewriter_obj, int api_mode)
{
    std::unique_lock<std::mutex> trackinglock(tracking_mutex);
    std::map<uint16_t, ul_sniffer_tracking_t>::iterator iter;

    std::stringstream msg; // BWS

    // auto now = std::chrono::system_clock::now();
	// std::time_t cur_time = std::chrono::system_clock::to_time_t(now);
	// std::string str_cur_time(std::ctime(&cur_time));
	// std::string cur_time_second = str_cur_time.substr(11,8);
	// msg << "[" << cur_time_second << "]: ";

    int nof_16qam = 0;
    int nof_64qam = 0;
    int nof_256qam = 0;
    int nof_unknown = 0;
    int num = 1;

    for (int i = 0; i < 86; i++)
    {
        msg << "-";
    }
    msg << std::endl;

    print_header_ul_mode(msg);

    for (int i = 0; i < 86; i++)
    {
        msg << "-";
    }
    msg << std::endl;

    for (iter = tracking_database_ul_mode.begin(); iter != tracking_database_ul_mode.end(); iter++)
    {
        if (iter->second.mcs_mod == UL_SNIFFER_16QAM_MAX && iter->second.nof_active > 0)
        {
            print_statistic_rnti_ul_mode(msg, iter, num, "16QAM");
            nof_16qam++;
            num++;
        }
    }
    for (iter = tracking_database_ul_mode.begin(); iter != tracking_database_ul_mode.end(); iter++)
    {
        if (iter->second.mcs_mod == UL_SNIFFER_64QAM_MAX && iter->second.nof_active > 0)
        {
            print_statistic_rnti_ul_mode(msg, iter, num, "64QAM");
            nof_64qam++;
            num++;
        }
    }
    for (iter = tracking_database_ul_mode.begin(); iter != tracking_database_ul_mode.end(); iter++)
    {
        if (iter->second.mcs_mod == UL_SNIFFER_256QAM_MAX && iter->second.nof_active > 0)
        {
            print_statistic_rnti_ul_mode(msg, iter, num, "256QAM");
            nof_256qam++;
            num++;
        }
    }
    for (int i = 0; i < 86; i++)
    {
        msg << "-";
    }
    msg << std::endl;

    print_header_ul_mode(msg);

    for (iter = tracking_database_ul_mode.begin(); iter != tracking_database_ul_mode.end(); iter++)
    {
        if (iter->second.mcs_mod == UL_SNIFFER_UNKNOWN_MOD && iter->second.nof_active > 0)
        {
            if ((iter->second.nof_unsupport_mimo == 0 && iter->second.nof_pinfo == 0 && iter->second.nof_other_mimo == 0 && iter->second.nof_active > 0))
            {
                print_statistic_rnti_ul_mode(msg, iter, num, "Unknown");
                nof_unknown++;
                num++;
            }
        }
    }

    for (int i = 0; i < 86; i++)
    {
        msg << "-";
    }
    msg << std::endl;

    for (iter = tracking_database_ul_mode.begin(); iter != tracking_database_ul_mode.end(); iter++)
    {
        if (iter->second.mcs_mod == UL_SNIFFER_UNKNOWN_MOD)
        {
            if ((iter->second.nof_active > 0) && !(iter->second.nof_unsupport_mimo == 0 && iter->second.nof_pinfo == 0 && iter->second.nof_other_mimo == 0))
            {
                print_statistic_rnti_ul_mode(msg, iter, num, "Unknown");
                nof_unknown++;
                num++;
            }
        }
    }
    
    // BWS
    msg << "[256Tracking] Total: ";
    msg << std::right << std::setw(6) << nof_64qam;
    msg << " RNTIs are 64QAM table, ";
    msg << std::right << std::setw(6) << nof_256qam;
    msg << " RNTIs are 256QAM table, ";
    msg << std::right << std::setw(6) << nof_unknown;
    msg << " RNTIs are Unknown ";
    msg << std::endl; 
    msg << std::endl;
    //printf("[256Tracking] Total: %d RNTIs are max 16QAM table, %d RNTIs are max 64QAM table, %d RNTIs are max 256QAM, %d RNTIs are Unknown \n\n",
    //       nof_16qam, nof_64qam, nof_256qam, nof_unknown);
    if(DEBUG_TABLE_PRINT==1 && api_mode == -1){
		std::cout << msg.str();
	}
    if(FILE_WRITE==1){
        filewriter_obj->write_stats(msg.str());
    }

    trackinglock.unlock();
}

void MCSTracking::print_all_database_ul(LTESniffer_stat_writer  *filewriter_obj, int api_mode)
{
    std::unique_lock<std::mutex> trackinglock(tracking_mutex);
    std::map<uint16_t, ul_sniffer_tracking_t>::iterator iter;

    std::stringstream msg; // BWS

    int nof_16qam = 0;
    int nof_64qam = 0;
    int nof_256qam = 0;
    int nof_unknown = 0;
    int num = 1;

    for (int i = 0; i < 86; i++)
    {
        msg << "-";
    }
    msg << std::endl;

    auto now = std::chrono::system_clock::now();
	std::time_t cur_time = std::chrono::system_clock::to_time_t(now);
	std::string str_cur_time(std::ctime(&cur_time));
	std::string cur_time_second;
	if(str_cur_time.length()>=(11+8)){
        cur_time_second = str_cur_time.substr(11,8);
    }else{
        cur_time_second = "";
    }
	msg << "[" << cur_time_second << "]: ";

    msg << std::left << std::setw(5) << "Num";
    msg << std::left << std::setw(9) << "RNTI";
    msg << std::left << std::setw(12) << "Max Mod";
    msg << std::left << std::setw(9) << "Active";
    msg << BOLDGREEN << std::left << std::setw(13) << "Success" << RESET;
    msg << std::left << std::setw(9) << "SNR(dB)";
    msg << std::left << std::setw(18) << "DL-UL_delay(us)";
    msg << std::left << std::setw(9) << "Other_Info";
    msg << std::endl;

    for (int i = 0; i < 86; i++)
    {
        msg << "-";
    }
    msg << std::endl;

    for (iter = all_database_ul_mode.begin(); iter != all_database_ul_mode.end(); iter++)
    {
        if (iter->second.mcs_mod == UL_SNIFFER_16QAM_MAX && iter->second.nof_active > 0)
        {
            nof_16qam++;
            msg << "            ";
            msg << std::left << std::setw(5) << num;
            msg << std::left << std::setw(9) << iter->first;
            msg << std::left << std::setw(12) << "16QAM";
            msg << std::left << std::setw(9) << iter->second.nof_active;
            int sc_percent = 0;
            if (iter->second.nof_active > 0)
            {
                sc_percent = std::roundf(((float)iter->second.nof_success_mgs / (float)iter->second.nof_active) * 100);
            }
            std::string sc_pc_str = std::to_string(iter->second.nof_success_mgs) + '(' + std::to_string(sc_percent) + "%)";
            msg << BOLDGREEN << std::left << std::setw(13) << sc_pc_str << RESET;
            float sum_snr = 0;
            float ave_snr = 0;
            if (iter->second.snr.size() > 0)
            {
                for (float x : iter->second.snr)
                {
                    sum_snr += x;
                }
                ave_snr = sum_snr / iter->second.snr.size();
            }
            msg << std::left << std::setw(9) << std::setprecision(3) << ave_snr;
            // iter->second.snr.clear();
            /*TA*/
            float sum_ta = 0;
            float ave_ta = 0;
            if (iter->second.ta.size() > 0)
            {
                for (float x : iter->second.ta)
                {
                    sum_ta += x;
                }
                ave_ta = sum_ta / iter->second.ta.size();
            }
            if (ave_ta >= 0)
            {
                msg << "+";
                msg << std::left << std::setw(17) << std::setprecision(3) << ave_ta;
            }
            else
            {
                msg << std::left << std::setw(18) << std::setprecision(3) << ave_ta;
            }
            msg << std::left << std::setw(9) << iter->second.nof_other_mimo;
            msg << std::endl;
            num++;
            // write_csv_file(iter->first, iter->second, iter->second.mcs_mod);
        }
    }
    for (iter = all_database_ul_mode.begin(); iter != all_database_ul_mode.end(); iter++)
    {
        if (iter->second.mcs_mod == UL_SNIFFER_64QAM_MAX && iter->second.nof_active > 0)
        {
            nof_64qam++;
            msg << "            ";
            msg << std::left << std::setw(5) << num;
            msg << std::left << std::setw(9) << iter->first;
            msg << std::left << std::setw(12) << "64QAM";
            msg << std::left << std::setw(9) << iter->second.nof_active;
            int sc_percent = 0;
            if (iter->second.nof_active > 0)
            {
                sc_percent = std::roundf(((float)iter->second.nof_success_mgs / (float)iter->second.nof_active) * 100);
            }
            std::string sc_pc_str = std::to_string(iter->second.nof_success_mgs) + '(' + std::to_string(sc_percent) + "%)";
            msg << BOLDGREEN << std::left << std::setw(13) << sc_pc_str << RESET;
            float sum_snr = 0;
            float ave_snr = 0;
            if (iter->second.snr.size() > 0)
            {
                for (float x : iter->second.snr)
                {
                    sum_snr += x;
                }
                ave_snr = sum_snr / iter->second.snr.size();
            }
            msg << std::left << std::setw(9) << std::setprecision(3) << ave_snr;
            // iter->second.snr.clear();
            /*TA*/
            float sum_ta = 0;
            float ave_ta = 0;
            if (iter->second.ta.size() > 0)
            {
                for (float x : iter->second.ta)
                {
                    sum_ta += x;
                }
                ave_ta = sum_ta / iter->second.ta.size();
            }
            if (ave_ta >= 0)
            {
                msg << "+";
                msg << std::left << std::setw(17) << std::setprecision(3) << ave_ta;
            }
            else
            {
                msg << std::left << std::setw(18) << std::setprecision(3) << ave_ta;
            }
            msg << std::left << std::setw(9) << iter->second.nof_other_mimo;
            msg << std::endl;
            num++;
            // write_csv_file(iter->first, iter->second, iter->second.mcs_mod);
        }
    }
    for (iter = all_database_ul_mode.begin(); iter != all_database_ul_mode.end(); iter++)
    {
        if (iter->second.mcs_mod == UL_SNIFFER_256QAM_MAX && iter->second.nof_active > 0)
        {
            msg << "            ";
            msg << std::left << std::setw(5) << num;
            msg << std::left << std::setw(9) << iter->first;
            msg << std::left << std::setw(12) << "256QAM";
            msg << std::left << std::setw(9) << iter->second.nof_active;
            int sc_percent = 0;
            if (iter->second.nof_active > 0)
            {
                sc_percent = std::roundf(((float)iter->second.nof_success_mgs / (float)iter->second.nof_active) * 100);
            }
            std::string sc_pc_str = std::to_string(iter->second.nof_success_mgs) + '(' + std::to_string(sc_percent) + "%)";
            msg << BOLDGREEN << std::left << std::setw(13) << sc_pc_str << RESET;
            float sum_snr = 0;
            float ave_snr = 0;
            if (iter->second.snr.size() > 0)
            {
                for (float x : iter->second.snr)
                {
                    sum_snr += x;
                }
                ave_snr = sum_snr / iter->second.snr.size();
            }
            msg << std::left << std::setw(9) << std::setprecision(3) << ave_snr;
            // iter->second.snr.clear();
            /*TA*/
            float sum_ta = 0;
            float ave_ta = 0;
            if (iter->second.ta.size() > 0)
            {
                for (float x : iter->second.ta)
                {
                    sum_ta += x;
                }
                ave_ta = sum_ta / iter->second.ta.size();
            }
            if (ave_ta >= 0)
            {
                msg << "+";
                msg << std::left << std::setw(17) << std::setprecision(3) << ave_ta;
            }
            else
            {
                msg << std::left << std::setw(18) << std::setprecision(3) << ave_ta;
            }
            msg << std::left << std::setw(9) << iter->second.nof_other_mimo;
            msg << std::endl;
            nof_256qam++;
            num++;
            // write_csv_file(iter->first, iter->second, iter->second.mcs_mod);
        }
    }
    for (int i = 0; i < 86; i++)
    {
        msg << "-";
    }
    msg << std::endl;

	msg << "[" << cur_time_second << "]: ";

    msg << std::left << std::setw(5) << "Num ";
    msg << std::left << std::setw(9) << "RNTI";
    msg << std::left << std::setw(12) << "Max Mod";
    msg << std::left << std::setw(9) << "Active";
    msg << BOLDGREEN << std::left << std::setw(13) << "Success" << RESET;
    msg << std::left << std::setw(9) << "SNR(dB)";
    msg << std::left << std::setw(18) << "DL-UL_delay(us)";
    msg << std::left << std::setw(9) << "Other_Info";
    msg << std::endl;

    for (iter = all_database_ul_mode.begin(); iter != all_database_ul_mode.end(); iter++)
    {
        if (iter->second.mcs_mod == UL_SNIFFER_UNKNOWN_MOD && iter->second.nof_active > 0)
        {
            if ((iter->second.nof_unsupport_mimo == 0 && iter->second.nof_pinfo == 0 && iter->second.nof_other_mimo == 0))
            {
                msg << "            ";
                msg << std::left << std::setw(5) << num;
                msg << std::left << std::setw(9) << iter->first;
                msg << std::left << std::setw(12) << "Unknown";
                msg << std::left << std::setw(9) << iter->second.nof_active;
                int sc_percent = 0;
                if (iter->second.nof_active > 0)
                {
                    sc_percent = std::roundf(((float)iter->second.nof_success_mgs / (float)iter->second.nof_active) * 100);
                }
                std::string sc_pc_str = std::to_string(iter->second.nof_success_mgs) + '(' + std::to_string(sc_percent) + "%)";
                msg << BOLDGREEN << std::left << std::setw(13) << sc_pc_str << RESET;
                float sum_snr = 0;
                float ave_snr = 0;
                if (iter->second.snr.size() > 0)
                {
                    for (float x : iter->second.snr)
                    {
                        sum_snr += x;
                    }
                    ave_snr = sum_snr / iter->second.snr.size();
                }
                msg << std::left << std::setw(9) << std::setprecision(3) << ave_snr;
                // iter->second.snr.clear();
                /*TA*/
                float sum_ta = 0;
                float ave_ta = 0;
                if (iter->second.ta.size() > 0)
                {
                    for (float x : iter->second.ta)
                    {
                        sum_ta += x;
                    }
                    ave_ta = sum_ta / iter->second.ta.size();
                }
                if (ave_ta >= 0)
                {
                    msg << "+";
                    msg << std::left << std::setw(17) << std::setprecision(3) << ave_ta;
                }
                else
                {
                    msg << std::left << std::setw(18) << std::setprecision(3) << ave_ta;
                }
                msg << std::left << std::setw(9) << iter->second.nof_other_mimo;
                msg << std::endl;
                nof_unknown++;
                num++;
                // write_csv_file(iter->first, iter->second, iter->second.mcs_mod);
            }
        }
    }

    for (int i = 0; i < 86; i++)
    {
        msg << "-";
    }
    msg << std::endl;

    for (iter = all_database_ul_mode.begin(); iter != all_database_ul_mode.end(); iter++)
    {
        if (iter->second.mcs_mod == UL_SNIFFER_UNKNOWN_MOD && iter->second.nof_active > 0)
        {
            if (!(iter->second.nof_unsupport_mimo == 0 && iter->second.nof_pinfo == 0 && iter->second.nof_other_mimo == 0))
            {
                msg << "            ";
                msg << std::left << std::setw(5) << num;
                msg << std::left << std::setw(9) << iter->first;
                msg << std::left << std::setw(12) << "Unknown";
                msg << std::left << std::setw(9) << iter->second.nof_active;
                int sc_percent = 0;
                if (iter->second.nof_newtx > 0)
                {
                    sc_percent = std::roundf(((float)iter->second.nof_success_mgs / (float)iter->second.nof_active) * 100);
                }
                std::string sc_pc_str = std::to_string(iter->second.nof_success_mgs) + '(' + std::to_string(sc_percent) + "%)";
                msg << BOLDGREEN << std::left << std::setw(13) << sc_pc_str << RESET;
                float sum_snr = 0;
                float ave_snr = 0;
                if (iter->second.snr.size() > 0)
                {
                    for (float x : iter->second.snr)
                    {
                        sum_snr += x;
                    }
                    ave_snr = sum_snr / iter->second.snr.size();
                }
                msg << std::left << std::setw(9) << std::setprecision(3) << ave_snr;
                // iter->second.snr.clear();
                /*TA*/
                float sum_ta = 0;
                float ave_ta = 0;
                if (iter->second.ta.size() > 0)
                {
                    for (float x : iter->second.ta)
                    {
                        sum_ta += x;
                    }
                    ave_ta = sum_ta / iter->second.ta.size();
                }
                if (ave_ta >= 0)
                {
                    msg << "+";
                    msg << std::left << std::setw(17) << std::setprecision(3) << ave_ta;
                }
                else
                {
                    msg << std::left << std::setw(18) << std::setprecision(3) << ave_ta;
                }
                msg << std::left << std::setw(9) << iter->second.nof_other_mimo;
                msg << std::endl;
                nof_unknown++;
                num++;
            }
        }
    }
    
    // BWS
    msg << "[256Tracking] Total: ";
    msg << std::right << std::setw(6) << nof_64qam;
    msg << " RNTIs are 64QAM table, ";
    msg << std::right << std::setw(6) << nof_256qam;
    msg << " RNTIs are 256QAM table, ";
    msg << std::right << std::setw(6) << nof_unknown;
    msg << " RNTIs are Unknown ";
    msg << std::endl; 
    msg << std::endl;
    //printf("[256Tracking] Total: %d RNTIs are max 16QAM table, %d RNTIs are max 64QAM table, %d RNTIs are max 256QAM, %d RNTIs are Unknown \n\n",
    //       nof_16qam, nof_64qam, nof_256qam, nof_unknown);
    if(DEBUG_TABLE_PRINT==1 && api_mode == -1){
		std::cout << msg.str();
	}
    if(FILE_WRITE==1){
        filewriter_obj->write_stats(msg.str());
    }

    trackinglock.unlock();
} // print_all_database_ul

void MCSTracking::update_statistic_ul(uint16_t RNTI,
                                      bool success,
                                      DCI_UL &decoding_mem,
                                      float snr,
                                      float ta)
{
    std::unique_lock<std::mutex> trackinglock(tracking_mutex);
    std::map<uint16_t, ul_sniffer_tracking_t>::iterator iter;
    iter = tracking_database_ul_mode.find(RNTI);
    if (iter == tracking_database_ul_mode.end())
    {
        add_RNTI_ul(RNTI, decoding_mem.mcs_mod);
    }
    iter = tracking_database_ul_mode.find(RNTI);
    if (iter != tracking_database_ul_mode.end())
    {
        iter->second.nof_active++;
        if (success)
        {
            iter->second.nof_success_mgs++;
        }
        iter->second.snr.push_back(snr);
        iter->second.ta.push_back(ta);
    }
    trackinglock.unlock();
}

/*____________DL 256QAM/64QAM tracking implementation_____________________________*/

dl_sniffer_mcs_table_t MCSTracking::find_tracking_info_RNTI_dl(uint16_t RNTI)
{

    std::unique_lock<std::mutex> trackinglock(tracking_mutex);
    std::map<uint16_t, dl_sniffer_mcs_tracking_t>::iterator iter;
    iter = tracking_database_dl_mode.find(RNTI);
    if ((nof_RNTI_member_dl() == 0) || (iter == tracking_database_dl_mode.end()))
    {
        if (nof_RNTI_member_dl() < max_size)
        {
            // add_RNTI(RNTI, DL_SNIFFER_UNKNOWN_TABLE);
            return DL_SNIFFER_UNKNOWN_TABLE;
        }
        else
        {
            return DL_SNIFFER_FULL_BUFFER;
        }
    }
    else
    {
        clock_t cur_time = clock();
        iter->second.time = cur_time;
        return iter->second.mcs_table;
    }
    trackinglock.unlock();
}

int MCSTracking::add_RNTI_dl(uint16_t RNTI, dl_sniffer_mcs_table_t mcs_table)
{
    clock_t cur_time = clock();
    dl_sniffer_mcs_tracking_t new_tracking;
    new_tracking.time = cur_time;
    new_tracking.mcs_table = mcs_table;
    new_tracking.ue_spec_config = default_ue_spec_config;
    new_tracking.ue_spec_config.has_ue_config = false;
    tracking_database_dl_mode.insert(std::pair<uint16_t, dl_sniffer_mcs_tracking_t>(RNTI, (std::move(new_tracking))));
    return SRSRAN_SUCCESS;
}

void MCSTracking::update_RNTI_dl(uint16_t RNTI, dl_sniffer_mcs_table_t mcs_table)
{
    std::unique_lock<std::mutex> trackinglock(tracking_mutex);
    std::map<uint16_t, dl_sniffer_mcs_tracking_t>::iterator iter;
    iter = tracking_database_dl_mode.find(RNTI);
    if (iter != tracking_database_dl_mode.end())
    {
        if (iter->second.has_rar)
        {
            if (iter->second.nof_msg_after_rar > rar_thresold)
            {
                iter->second.mcs_table = mcs_table;
                iter->second.has_rar = false;
            }
            else
            {
                iter->second.mcs_table = DL_SNIFFER_UNKNOWN_TABLE;
            }
        }
        else
        {
            iter->second.mcs_table = mcs_table;
        }
    }
    else
    {
        add_RNTI_dl(RNTI, DL_SNIFFER_UNKNOWN_TABLE);
    }
    trackinglock.unlock();
}

void MCSTracking::update_rar_time_crnti(uint16_t crnti, clock_t cur_time)
{
    std::unique_lock<std::mutex> trackinglock(tracking_mutex);
    std::map<uint16_t, dl_sniffer_mcs_tracking_t>::iterator iter;
    iter = tracking_database_dl_mode.find(crnti);
    if (iter != tracking_database_dl_mode.end())
    {
        iter->second.has_rar = true;
        iter->second.mcs_table = DL_SNIFFER_UNKNOWN_TABLE;
        // iter->second.rar_time = cur_time;
    }
    else
    {
        add_RNTI_dl(crnti, DL_SNIFFER_UNKNOWN_TABLE);
        iter = tracking_database_dl_mode.find(crnti);
        iter->second.has_rar = true;
        iter->second.mcs_table = DL_SNIFFER_UNKNOWN_TABLE;
        // iter->second.rar_time   = cur_time;
    }
    trackinglock.unlock();
}

void MCSTracking::update_database_dl()
{
    std::unique_lock<std::mutex> trackinglock(tracking_mutex);
    std::vector<uint16_t> del_list;
    clock_t cur_time = clock();
    long double cur_interval = 0;
    std::map<uint16_t, dl_sniffer_mcs_tracking_t>::iterator iter;
    for (iter = tracking_database_dl_mode.begin(); iter != tracking_database_dl_mode.end(); iter++)
    {
        clock_t last_time = iter->second.time;
        cur_interval = (long double)((cur_time - last_time) / CLOCKS_PER_SEC);
        float cur_success_rate = (float)iter->second.nof_success_mgs / (float)iter->second.nof_active;
        bool wrong_detect = false; // wrong detection if decode wrong mimo multiple times

        /*Only add to final data base if there was no error when decoding PDSCH and nof_active = 0*/
        if ((iter->second.nof_active == 0) || (iter->second.nof_active <= 10 && iter->second.nof_success_mgs == 0 &&
                                               (iter->second.nof_unsupport_mimo > 0 || iter->second.nof_pinfo > 0 || iter->second.nof_other_mimo > 0)))
        {
            wrong_detect = true;
            iter->second.to_all_database = false;
        }
        /*delete from 10-seconds database if inactive during time interval or wrong detection or nof_active = 0*/
        if (cur_interval > interval || wrong_detect || iter->second.nof_active == 0)
        {
            del_list.push_back(iter->first);
        }
        else
        {
            if (cur_success_rate < (float)0.15 && iter->second.mcs_table != DL_SNIFFER_UNKNOWN_TABLE)
            { // if success rate lower than 15%, reset mcs table
                iter->second.mcs_table = DL_SNIFFER_UNKNOWN_TABLE;
            }
        }
    }
    if (del_list.size() != 0)
    {
        std::vector<uint16_t>::iterator iter;
        std::map<uint16_t, dl_sniffer_mcs_tracking_t>::iterator del_iter;
        for (iter = del_list.begin(); iter != del_list.end(); iter++)
        {
            del_iter = tracking_database_dl_mode.find(*iter);
            /*Update RNTI to final database (this database will not be deleted)*/
            if (del_iter->second.to_all_database)
            {
                auto add_iter = all_database_dl_mode.find(*iter);
                if (add_iter != all_database_dl_mode.end())
                {
                    add_iter->second.nof_active += del_iter->second.nof_active;
                    add_iter->second.nof_newtx += del_iter->second.nof_newtx;
                    add_iter->second.nof_success_mgs += del_iter->second.nof_success_mgs;
                    add_iter->second.nof_retx += del_iter->second.nof_retx;
                    add_iter->second.nof_success_retx_nom += del_iter->second.nof_success_retx_nom;
                    add_iter->second.nof_success_retx_harq += del_iter->second.nof_success_retx_harq;
                    add_iter->second.nof_success_retx += del_iter->second.nof_success_retx;
                    add_iter->second.nof_unsupport_mimo += del_iter->second.nof_unsupport_mimo;
                    for (int mcs_idx = 0; mcs_idx < DL_SNIFFER_NOF_MCS; mcs_idx++)
                    {
                        add_iter->second.mcs[mcs_idx] += del_iter->second.mcs[mcs_idx];
                        add_iter->second.mcs_sc[mcs_idx] += del_iter->second.mcs_sc[mcs_idx];
                    }
                }
                else
                {
                    dl_sniffer_mcs_tracking_t temp_tracking = {};
                    temp_tracking = del_iter->second;
                    uint16_t temp_rnti = del_iter->first;
                    std::pair<uint16_t, dl_sniffer_mcs_tracking_t> temp_pair(temp_rnti, temp_tracking);
                    all_database_dl_mode.insert(std::move(temp_pair));
                }
            }
            if (del_iter != tracking_database_dl_mode.end())
            {
                tracking_database_dl_mode.erase(del_iter);
            }
        }
    }
    trackinglock.unlock();
}

void MCSTracking::merge_all_database_dl()
{
    std::unique_lock<std::mutex> trackinglock(tracking_mutex);
    std::map<uint16_t, dl_sniffer_mcs_tracking_t>::iterator merge_iter;
    for (merge_iter = tracking_database_dl_mode.begin(); merge_iter != tracking_database_dl_mode.end(); merge_iter++)
    {
        auto add_iter = all_database_dl_mode.find(merge_iter->first);
        if (add_iter != all_database_dl_mode.end())
        {
            add_iter->second.nof_active += merge_iter->second.nof_active;
            add_iter->second.nof_newtx += merge_iter->second.nof_newtx;
            add_iter->second.nof_success_mgs += merge_iter->second.nof_success_mgs;
            add_iter->second.nof_retx += merge_iter->second.nof_retx;
            add_iter->second.nof_success_retx_nom += merge_iter->second.nof_success_retx_nom;
            add_iter->second.nof_success_retx_harq += merge_iter->second.nof_success_retx_harq;
            add_iter->second.nof_success_retx += merge_iter->second.nof_success_retx;
            add_iter->second.nof_unsupport_mimo += merge_iter->second.nof_unsupport_mimo;
            for (int mcs_idx = 0; mcs_idx < DL_SNIFFER_NOF_MCS; mcs_idx++)
            {
                add_iter->second.mcs[mcs_idx] += merge_iter->second.mcs[mcs_idx];
                add_iter->second.mcs_sc[mcs_idx] += merge_iter->second.mcs_sc[mcs_idx];
            }
        }
        else
        {
            dl_sniffer_mcs_tracking_t temp_tracking = {};
            temp_tracking = merge_iter->second;
            uint16_t temp_rnti = merge_iter->first;
            std::pair<uint16_t, dl_sniffer_mcs_tracking_t> temp_pair(temp_rnti, temp_tracking);
            all_database_dl_mode.insert(std::move(temp_pair));
        }
    }

    trackinglock.unlock();
}

void print_statistic_rnti(std::stringstream &msg,std::map<uint16_t, dl_sniffer_mcs_tracking_t>::iterator iter, int num, std::string info)
{
    msg << "            ";
    msg << std::left << std::setw(5) << num;
    msg << std::left << std::setw(9) << iter->first;
    msg << std::left << std::setw(12) << info;
    msg << std::left << std::setw(9) << iter->second.nof_active;
    msg << std::left << std::setw(9) << iter->second.nof_newtx;
    msg << std::left << std::setw(9) << iter->second.nof_retx;
    msg << std::left << std::setw(9) << iter->second.nof_success_mgs;
    msg << std::left << std::setw(9) << iter->second.nof_success_retx_harq;
    msg << std::left << std::setw(9) << iter->second.nof_success_retx_nom;
    msg << std::left << std::setw(9) << iter->second.nof_unsupport_mimo;
    msg << std::left << std::setw(9) << iter->second.nof_pinfo;
    msg << std::left << std::setw(9) << iter->second.nof_other_mimo;
    msg << std::endl;
}

void print_header(std::stringstream &msg)
{
    auto now = std::chrono::system_clock::now();
	std::time_t cur_time = std::chrono::system_clock::to_time_t(now);
	std::string str_cur_time(std::ctime(&cur_time));
	std::string cur_time_second;
	if(str_cur_time.length()>=(11+8)){
        cur_time_second = str_cur_time.substr(11,8);
    }else{
        cur_time_second = "";
    }
	msg << "[" << cur_time_second << "]: ";

    msg << std::left << std::setw(5) << "Num";
    msg << std::left << std::setw(9) << "RNTI";
    msg << std::left << std::setw(12) << "Table";
    msg << std::left << std::setw(9) << "Active";
    msg << std::left << std::setw(9) << "New TX";
    msg << std::left << std::setw(9) << "ReTX";
    msg << std::left << std::setw(9) << "Success";
    msg << std::left << std::setw(9) << "HARQ";
    msg << std::left << std::setw(9) << "Normal";
    msg << std::left << std::setw(9) << "W_MIMO";
    msg << std::left << std::setw(9) << "W_pinfor";
    msg << std::left << std::setw(9) << "Other ";
    msg << std::endl;
}

void MCSTracking::print_database_dl(LTESniffer_stat_writer  *filewriter_obj, int api_mode)
{
    std::unique_lock<std::mutex> trackinglock(tracking_mutex);
    std::map<uint16_t, dl_sniffer_mcs_tracking_t>::iterator iter;
    
    std::stringstream msg; // BWS

    // auto now = std::chrono::system_clock::now();
	// std::time_t cur_time = std::chrono::system_clock::to_time_t(now);
	// std::string str_cur_time(std::ctime(&cur_time));
	// std::string cur_time_second = str_cur_time.substr(11,8);
	// msg << "[" << cur_time_second << "]: ";

    int nof_64qam = 0;
    int nof_256qam = 0;
    int nof_unknown = 0;
    int num = 1;

    for (int i = 0; i < 104; i++)
    {
        msg << "-";
    }
    msg << std::endl;

    print_header(msg);

    for (int i = 0; i < 104; i++)
    {
        msg << "-";
    }
    msg << std::endl;
    for (iter = tracking_database_dl_mode.begin(); iter != tracking_database_dl_mode.end(); iter++)
    {
        if (iter->second.mcs_table == DL_SNIFFER_64QAM_TABLE)
        {
            nof_64qam++;
            print_statistic_rnti(msg, iter, num, "64QAM");
            num++;
        }
    }
    for (iter = tracking_database_dl_mode.begin(); iter != tracking_database_dl_mode.end(); iter++)
    {
        if (iter->second.mcs_table == DL_SNIFFER_256QAM_TABLE)
        {
            print_statistic_rnti(msg, iter, num, "256QAM");
            nof_256qam++;
            num++;
        }
    }
    for (int i = 0; i < 104; i++)
    {
        msg << "-";
    }
    msg << std::endl;

    print_header(msg);
    for (iter = tracking_database_dl_mode.begin(); iter != tracking_database_dl_mode.end(); iter++)
    {
        if (iter->second.mcs_table == DL_SNIFFER_UNKNOWN_TABLE)
        {
            /*iter->second.nof_active > 0: some RNTIs have nof_active = 0 due to only obatained from rar message only, no other actives*/
            if ((iter->second.nof_unsupport_mimo == 0 && iter->second.nof_pinfo == 0 && iter->second.nof_other_mimo == 0 && iter->second.nof_active > 0))
            {
                print_statistic_rnti(msg, iter, num, "Unknown");
                nof_unknown++;
                num++;
            }
        }
    }

    for (int i = 0; i < 104; i++)
    {
        msg << "-";
    }
    msg << std::endl;

    for (iter = tracking_database_dl_mode.begin(); iter != tracking_database_dl_mode.end(); iter++)
    {
        if (iter->second.mcs_table == DL_SNIFFER_UNKNOWN_TABLE)
        {
            /*iter->second.nof_active > 0: some RNTIs have nof_active = 0 due to only obatained from rar message only, no other actives*/
            if (!(iter->second.nof_unsupport_mimo == 0 && iter->second.nof_pinfo == 0 && iter->second.nof_other_mimo == 0) && iter->second.nof_active > 0)
            {
                print_statistic_rnti(msg, iter, num, "Unknown");
                nof_unknown++;
                num++;
            }
        }
    }

    // BWS
    msg << "[256Tracking] Total: ";
    msg << std::right << std::setw(6) << nof_64qam;
    msg << " RNTIs are 64QAM table, ";
    msg << std::right << std::setw(6) << nof_256qam;
    msg << " RNTIs are 256QAM table, ";
    msg << std::right << std::setw(6) << nof_unknown;
    msg << " RNTIs are Unknown ";
    msg << std::endl; 
    msg << std::endl;
    //printf("[256Tracking] Total: %d RNTIs are 64QAM table, %d RNTIs are 256QAM table, %d RNTIs are Unknown \n\n",
    //       nof_64qam, nof_256qam, nof_unknown);
    if(DEBUG_TABLE_PRINT==1 && api_mode == -1){
		std::cout << msg.str();
	}
    if(FILE_WRITE==1){
        filewriter_obj->write_stats(msg.str());
    }

    trackinglock.unlock();
} // print_database_dl

void MCSTracking::print_all_database_dl(LTESniffer_stat_writer  *filewriter_obj, int api_mode)
{
    std::unique_lock<std::mutex> trackinglock(tracking_mutex);
    std::map<uint16_t, dl_sniffer_mcs_tracking_t>::iterator iter;

    std::stringstream msg; // BWS

    int nof_64qam = 0;
    int nof_256qam = 0;
    int nof_unknown = 0;
    int num = 1;

    for (int i = 0; i < 109; i++)
    {
        msg << "-";
    }
    msg << std::endl;

    auto now = std::chrono::system_clock::now();
	std::time_t cur_time = std::chrono::system_clock::to_time_t(now);
	std::string str_cur_time(std::ctime(&cur_time));
	std::string cur_time_second;
	if(str_cur_time.length()>=(11+8)){
        cur_time_second = str_cur_time.substr(11,8);
    }else{
        cur_time_second = "";
    }
	msg << "[" << cur_time_second << "]: ";

    msg << std::left << std::setw(5) << "Num";
    msg << std::left << std::setw(9) << "RNTI";
    msg << std::left << std::setw(12) << "Table";
    msg << std::left << std::setw(9) << "Active";
    msg << RED << std::left << std::setw(9) << "New TX" << RESET;
    msg << std::left << std::setw(9) << "ReTX";
    msg << BOLDGREEN << std::left << std::setw(13) << "Success" << RESET;
    msg << std::left << std::setw(9) << "HARQ";
    msg << std::left << std::setw(9) << "Normal";
    msg << std::left << std::setw(9) << "W_MIMO";
    msg << std::left << std::setw(9) << "W_pinfor";
    msg << std::left << std::setw(9) << "Other ";
    msg << std::endl;

    for (int i = 0; i < 109; i++)
    {
        msg << "-";
    }
    msg << std::endl;

    for (iter = all_database_dl_mode.begin(); iter != all_database_dl_mode.end(); iter++)
    {
        if (iter->second.mcs_table == DL_SNIFFER_64QAM_TABLE)
        {
            nof_64qam++;
            msg << "            ";
            msg << std::left << std::setw(5) << num;
            msg << std::left << std::setw(9) << iter->first;
            msg << std::left << std::setw(12) << "64QAM";
            msg << std::left << std::setw(9) << iter->second.nof_active;
            msg << RED << std::left << std::setw(9) << iter->second.nof_newtx << RESET;
            msg << std::left << std::setw(9) << iter->second.nof_retx;
            int sc_percent = 0;
            if (iter->second.nof_newtx > 0)
            {
                sc_percent = std::roundf(((float)iter->second.nof_success_mgs / (float)iter->second.nof_active) * 100);
            }
            std::string sc_pc_str = std::to_string(iter->second.nof_success_mgs) + '(' + std::to_string(sc_percent) + "%)";
            msg << BOLDGREEN << std::left << std::setw(13) << sc_pc_str << RESET;
            msg << std::left << std::setw(9) << iter->second.nof_success_retx_harq;
            msg << std::left << std::setw(9) << iter->second.nof_success_retx_nom;
            msg << std::left << std::setw(9) << iter->second.nof_unsupport_mimo;
            msg << std::left << std::setw(9) << iter->second.nof_pinfo;
            msg << std::left << std::setw(9) << iter->second.nof_other_mimo;
            msg << std::endl;
            num++;
            write_csv_file(iter->first, iter->second, iter->second.mcs_table);
        }
    }
    for (iter = all_database_dl_mode.begin(); iter != all_database_dl_mode.end(); iter++)
    {
        if (iter->second.mcs_table == DL_SNIFFER_256QAM_TABLE)
        {
            msg << "            ";
            msg << std::left << std::setw(5) << num;
            msg << std::left << std::setw(9) << iter->first;
            msg << std::left << std::setw(12) << "256QAM";
            msg << std::left << std::setw(9) << iter->second.nof_active;
            msg << RED << std::left << std::setw(9) << iter->second.nof_newtx << RESET;
            msg << std::left << std::setw(9) << iter->second.nof_retx;
            int sc_percent = 0;
            if (iter->second.nof_newtx > 0)
            {
                sc_percent = std::roundf(((float)iter->second.nof_success_mgs / (float)iter->second.nof_active) * 100);
            }
            std::string sc_pc_str = std::to_string(iter->second.nof_success_mgs) + '(' + std::to_string(sc_percent) + "%)";
            msg << BOLDGREEN << std::left << std::setw(13) << sc_pc_str << RESET;
            msg << std::left << std::setw(9) << iter->second.nof_success_retx_harq;
            msg << std::left << std::setw(9) << iter->second.nof_success_retx_nom;
            msg << std::left << std::setw(9) << iter->second.nof_unsupport_mimo;
            msg << std::left << std::setw(9) << iter->second.nof_pinfo;
            msg << std::left << std::setw(9) << iter->second.nof_other_mimo;
            msg << std::endl;
            nof_256qam++;
            num++;
            write_csv_file(iter->first, iter->second, iter->second.mcs_table);
        }
    }
    for (int i = 0; i < 109; i++)
    {
        msg << "-";
    }
    msg << std::endl;

	msg << "[" << cur_time_second << "]: ";

    msg << std::left << std::setw(5) << "Num ";
    msg << std::left << std::setw(9) << "RNTI";
    msg << std::left << std::setw(12) << "Table";
    msg << std::left << std::setw(9) << "Active";
    msg << RED << std::left << std::setw(9) << "New TX" << RESET;
    msg << std::left << std::setw(9) << "ReTX";
    msg << BOLDGREEN << std::left << std::setw(13) << "Success" << RESET;
    msg << std::left << std::setw(9) << "HARQ";
    msg << std::left << std::setw(9) << "Normal";
    msg << std::left << std::setw(9) << "W_MIMO";
    msg << std::left << std::setw(9) << "W_pinfor";
    msg << std::left << std::setw(9) << "Other";
    msg << std::endl;

    for (iter = all_database_dl_mode.begin(); iter != all_database_dl_mode.end(); iter++)
    {
        if (iter->second.mcs_table == DL_SNIFFER_UNKNOWN_TABLE)
        {
            if ((iter->second.nof_unsupport_mimo == 0 && iter->second.nof_pinfo == 0 && iter->second.nof_other_mimo == 0 && iter->second.nof_active > 0))
            {
                msg << "            ";
                msg << std::left << std::setw(5) << num;
                msg << std::left << std::setw(9) << iter->first;
                msg << std::left << std::setw(12) << "Unknown";
                msg << std::left << std::setw(9) << iter->second.nof_active;
                msg << RED << std::left << std::setw(9) << iter->second.nof_newtx << RESET;
                msg << std::left << std::setw(9) << iter->second.nof_retx;
                int sc_percent = 0;
                if (iter->second.nof_newtx > 0)
                {
                    sc_percent = std::roundf(((float)iter->second.nof_success_mgs / (float)iter->second.nof_active) * 100);
                }
                std::string sc_pc_str = std::to_string(iter->second.nof_success_mgs) + '(' + std::to_string(sc_percent) + "%)";
                msg << BOLDGREEN << std::left << std::setw(13) << sc_pc_str << RESET;
                msg << std::left << std::setw(9) << iter->second.nof_success_retx_harq;
                msg << std::left << std::setw(9) << iter->second.nof_success_retx_nom;
                msg << std::left << std::setw(9) << iter->second.nof_unsupport_mimo;
                msg << std::left << std::setw(9) << iter->second.nof_pinfo;
                msg << std::left << std::setw(9) << iter->second.nof_other_mimo;
                msg << std::endl;
                nof_unknown++;
                num++;
                write_csv_file(iter->first, iter->second, iter->second.mcs_table);
            }
        }
    }

    for (int i = 0; i < 109; i++)
    {
        msg << "-";
    }
    msg << std::endl;

    for (iter = all_database_dl_mode.begin(); iter != all_database_dl_mode.end(); iter++)
    {
        if (iter->second.mcs_table == DL_SNIFFER_UNKNOWN_TABLE)
        {
            if ((iter->second.nof_active > 0) && !(iter->second.nof_unsupport_mimo == 0 && iter->second.nof_pinfo == 0 && iter->second.nof_other_mimo == 0))
            {
                msg << "            ";
                msg << std::left << std::setw(5) << num;
                msg << std::left << std::setw(9) << iter->first;
                msg << std::left << std::setw(12) << "Unknown";
                msg << std::left << std::setw(9) << iter->second.nof_active;
                msg << RED << std::left << std::setw(9) << iter->second.nof_newtx << RESET;
                msg << std::left << std::setw(9) << iter->second.nof_retx;
                int sc_percent = 0;
                if (iter->second.nof_newtx > 0)
                {
                    sc_percent = std::roundf(((float)iter->second.nof_success_mgs / (float)iter->second.nof_active) * 100);
                }
                std::string sc_pc_str = std::to_string(iter->second.nof_success_mgs) + '(' + std::to_string(sc_percent) + "%)";
                msg << BOLDGREEN << std::left << std::setw(13) << sc_pc_str << RESET;
                msg << std::left << std::setw(9) << iter->second.nof_success_retx_harq;
                msg << std::left << std::setw(9) << iter->second.nof_success_retx_nom;
                msg << std::left << std::setw(9) << iter->second.nof_unsupport_mimo;
                msg << std::left << std::setw(9) << iter->second.nof_pinfo;
                msg << std::left << std::setw(9) << iter->second.nof_other_mimo;
                msg << std::endl;
                nof_unknown++;
                num++;
            }
        }
    }

    msg << "[256Tracking] Total: ";
    msg << std::right << std::setw(6) << nof_64qam;
    msg << " RNTIs are 64QAM table, ";
    msg << std::right << std::setw(6) << nof_256qam;
    msg << " RNTIs are 256QAM table, ";
    msg << std::right << std::setw(6) << nof_unknown;
    msg << " RNTIs are Unknown ";
    msg << std::endl; 
    msg << std::endl;
    // BWS
    //printf("[256Tracking] Total: %d RNTIs are 64QAM table, %d RNTIs are 256QAM table, %d RNTIs are Unknown \n\n",
    //       nof_64qam, nof_256qam, nof_unknown);
    if(DEBUG_TABLE_PRINT==1 && api_mode == -1){
		std::cout << msg.str();
	}
    if(FILE_WRITE==1){
        filewriter_obj->write_stats(msg.str());
    }

    trackinglock.unlock();
} // print_all_database_dl

void MCSTracking::update_statistic_dl(uint16_t RNTI,
                                      bool tb_en[SRSRAN_MAX_CODEWORDS],
                                      int transmission_type[SRSRAN_MAX_CODEWORDS],
                                      bool success[SRSRAN_MAX_CODEWORDS],
                                      DL_Sniffer_DCI_DL &decoding_mem,
                                      int mimo_ret,
                                      srsran_pdsch_grant_t *statistic_grant)
{
    std::unique_lock<std::mutex> trackinglock(tracking_mutex);
    std::map<uint16_t, dl_sniffer_mcs_tracking_t>::iterator iter;
    iter = tracking_database_dl_mode.find(RNTI);
    if (iter == tracking_database_dl_mode.end())
    {
        add_RNTI_dl(RNTI, DL_SNIFFER_UNKNOWN_TABLE);
    }
    iter = tracking_database_dl_mode.find(RNTI);
    if (iter != tracking_database_dl_mode.end())
    {
        /*Update number of messages with DCI > 1A after RAR*/
        if (decoding_mem.format > SRSRAN_DCI_FORMAT1A && iter->second.has_rar)
        {
            iter->second.nof_msg_after_rar++;
        }
        if (decoding_mem.mcs_table == DL_SNIFFER_64QAM_TABLE || decoding_mem.mcs_table == DL_SNIFFER_256QAM_TABLE)
        {
            for (int i = 0; i < SRSRAN_MAX_CODEWORDS; i++)
            {
                if (tb_en[i])
                {
                    iter->second.nof_active++;
                }
                if (tb_en[i] && (transmission_type[i] == DL_SNIFFER_NEW_TX || transmission_type[i] == DL_SNIFFER_HARQ_FULL_BUFFER || transmission_type[i] == DL_SNIFFER_HARQ_BUSY))
                {
                    if (statistic_grant->tb[i].mcs_idx <= 28 && decoding_mem.mcs_table == DL_SNIFFER_64QAM_TABLE && harq_mode)
                    {
                        iter->second.nof_newtx++;
                    }
                    else if (statistic_grant->tb[i].mcs_idx <= 27 && decoding_mem.mcs_table == DL_SNIFFER_256QAM_TABLE && harq_mode)
                    {
                        iter->second.nof_newtx++;
                    }
                    else if (!harq_mode)
                    {
                        iter->second.nof_newtx++;
                    }
                }
                else if (tb_en[i] && (transmission_type[i] == DL_SNIFFER_RE_TX || transmission_type[i] == DL_SNIFFER_DECODED ||
                                      (statistic_grant->tb[i].mcs_idx > 28 && decoding_mem.mcs_table == DL_SNIFFER_64QAM_TABLE) ||
                                      (statistic_grant->tb[i].mcs_idx > 27 && decoding_mem.mcs_table == DL_SNIFFER_256QAM_TABLE)))
                {
                    iter->second.nof_retx++;
                }
                if (success[i])
                {
                    iter->second.nof_success_mgs++;
                    if (transmission_type[i] == DL_SNIFFER_RE_TX)
                    {
                        iter->second.nof_success_retx_harq++;
                    }
                }
                if (transmission_type[i] == DL_SNIFFER_DECODED && success[i] == false)
                {
                    iter->second.nof_success_mgs++;
                }

                if ((success[i] && transmission_type[i] == DL_SNIFFER_RE_TX) || (transmission_type[i] == DL_SNIFFER_DECODED))
                {
                    iter->second.nof_success_retx++;
                }
                if (transmission_type[i] == DL_SNIFFER_DECODED)
                {
                    iter->second.nof_success_retx_nom++;
                }
                if (mimo_ret == DL_SNIFFER_MIMO_NOT_SUPPORT && tb_en[i])
                {
                    iter->second.nof_unsupport_mimo++;
                }
                else if (mimo_ret == DL_SNIFFER_PMI_WRONG && tb_en[i])
                {
                    iter->second.nof_pinfo++;
                }
                else if (mimo_ret == DL_SNIFFER_LAYER_WRONG && tb_en[i])
                {
                    iter->second.nof_other_mimo++;
                }
            }
        }
        else if (decoding_mem.mcs_table == DL_SNIFFER_UNKNOWN_TABLE)
        {
            for (int i = 0; i < SRSRAN_MAX_CODEWORDS; i++)
            {
                if (tb_en[i])
                {
                    iter->second.nof_active++;
                    iter->second.nof_newtx++;
                }
                if (success[i])
                {
                    iter->second.nof_success_mgs++;
                }
                if (mimo_ret == DL_SNIFFER_MIMO_NOT_SUPPORT && tb_en[i])
                {
                    iter->second.nof_unsupport_mimo++;
                }
                else if (mimo_ret == DL_SNIFFER_PMI_WRONG && tb_en[i])
                {
                    iter->second.nof_pinfo++;
                }
                else if (mimo_ret == DL_SNIFFER_LAYER_WRONG && tb_en[i])
                {
                    iter->second.nof_other_mimo++;
                }
            }
        }
        for (int mcs_idx = 0; mcs_idx < DL_SNIFFER_NOF_MCS; mcs_idx++)
        {
            for (int cw = 0; cw < SRSRAN_MAX_CODEWORDS; cw++)
            {
                if (tb_en[cw])
                {
                    if (statistic_grant->tb[cw].mcs_idx == mcs_idx)
                    {
                        iter->second.mcs[mcs_idx]++;
                        if (success[cw])
                        {
                            iter->second.mcs_sc[mcs_idx]++;
                        }
                        if (!success[cw] && transmission_type[cw] == DL_SNIFFER_DECODED)
                        {
                            iter->second.mcs_sc[mcs_idx]++;
                        }
                    }
                }
            }
        }
    }
    trackinglock.unlock();
}

bool MCSTracking::get_debug_mode()
{
    std::unique_lock<std::mutex> trackingLock(tracking_mutex);
    return en_debug;
}

void MCSTracking::write_csv_file(uint16_t rnti, dl_sniffer_mcs_tracking_t &statistic, int table)
{
    std::string table_str;
    if (table == DL_SNIFFER_64QAM_TABLE)
    {
        table_str = "64QAM";
    }
    else if (table == DL_SNIFFER_256QAM_TABLE)
    {
        table_str = "256QAM";
    }
    else if (table == UL_SNIFFER_UNKNOWN_MOD)
    {
        table_str = "Unknown";
    }
    int sc_percent = std::roundf(((float)statistic.nof_success_mgs / (float)statistic.nof_newtx) * 100);
    csv_file << rnti << ',' << table_str << ',' << statistic.nof_newtx << ',' << statistic.nof_success_mgs << ',' << sc_percent << ',';
    for (int mcs_idx = 0; mcs_idx < DL_SNIFFER_NOF_MCS; mcs_idx++)
    {
        int sc_percent = 0;
        if (statistic.mcs[mcs_idx] > 0)
        {
            sc_percent = std::roundf(((float)statistic.mcs_sc[mcs_idx] / (float)statistic.mcs[mcs_idx]) * 100);
        }
        std::string mcs_sc_str = std::to_string(statistic.mcs_sc[mcs_idx]) + '/' + std::to_string(statistic.mcs[mcs_idx]) + '=' + std::to_string(sc_percent) + '%';
        csv_file << mcs_sc_str << ',';
    }
    csv_file << "\n";
}

/*__________________Manage UE Specific Configuation___________________*/

void MCSTracking::update_ue_config_rnti(uint16_t rnti, ltesniffer_ue_spec_config_t ue_spec_config)
{
    std::unique_lock<std::mutex> trackinglock(tracking_mutex);
    if (sniffer_mode == DL_MODE)
    {
        std::map<uint16_t, dl_sniffer_mcs_tracking_t>::iterator dl_iter;
        dl_iter = tracking_database_dl_mode.find(rnti);
        if (dl_iter != tracking_database_dl_mode.end())
        {
            dl_iter->second.ue_spec_config = ue_spec_config;
        }
        else
        {
            add_RNTI_dl(rnti, DL_SNIFFER_UNKNOWN_TABLE);
            dl_iter = tracking_database_dl_mode.find(rnti);
            dl_iter->second.ue_spec_config = ue_spec_config;
        }
    }
    else if (sniffer_mode == UL_MODE)
    {
        std::map<uint16_t, ul_sniffer_tracking_t>::iterator ul_iter;
        ul_iter = tracking_database_ul_mode.find(rnti);
        if (ul_iter != tracking_database_ul_mode.end())
        {
            ul_iter->second.ue_spec_config = ue_spec_config;
        }
        else
        {
            add_RNTI_ul(rnti, UL_SNIFFER_UNKNOWN_MOD);
            ul_iter = tracking_database_ul_mode.find(rnti);
            ul_iter->second.ue_spec_config = ue_spec_config;
        }
    }
    else if (sniffer_mode == DL_UL_MODE) // BWS
    {
        // Downlink
        std::map<uint16_t, dl_sniffer_mcs_tracking_t>::iterator dl_iter;
        dl_iter = tracking_database_dl_mode.find(rnti);
        if (dl_iter != tracking_database_dl_mode.end())
        {
            dl_iter->second.ue_spec_config = ue_spec_config;
        }
        else
        {
            add_RNTI_dl(rnti, DL_SNIFFER_UNKNOWN_TABLE);
            dl_iter = tracking_database_dl_mode.find(rnti);
            dl_iter->second.ue_spec_config = ue_spec_config;
        }
        // Uplink
        std::map<uint16_t, ul_sniffer_tracking_t>::iterator ul_iter;
        ul_iter = tracking_database_ul_mode.find(rnti);
        if (ul_iter != tracking_database_ul_mode.end())
        {
            ul_iter->second.ue_spec_config = ue_spec_config;
        }
        else
        {
            add_RNTI_ul(rnti, UL_SNIFFER_UNKNOWN_MOD);
            ul_iter = tracking_database_ul_mode.find(rnti);
            ul_iter->second.ue_spec_config = ue_spec_config;
        }
    }
    trackinglock.unlock();
}

ltesniffer_ue_spec_config_t MCSTracking::get_ue_config_rnti(uint16_t rnti, int DL_or_UL)
{
    std::unique_lock<std::mutex> trackinglock(tracking_mutex);
    ltesniffer_ue_spec_config_t ue_spec_config = {};
    ue_spec_config = default_ue_spec_config;
    ue_spec_config.has_ue_config = false;
    if (DL_or_UL == 0) // BWS
    {
        std::map<uint16_t, dl_sniffer_mcs_tracking_t>::iterator dl_iter;
        dl_iter = tracking_database_dl_mode.find(rnti);
        if (dl_iter != tracking_database_dl_mode.end())
        {
            ue_spec_config = dl_iter->second.ue_spec_config;
        }
        else
        {
            // nothing
        }
    }
    else if (DL_or_UL == 1) // BWS
    {
        std::map<uint16_t, ul_sniffer_tracking_t>::iterator ul_iter;
        ul_iter = tracking_database_ul_mode.find(rnti);
        if (ul_iter != tracking_database_ul_mode.end())
        {
            ue_spec_config = ul_iter->second.ue_spec_config;
        }
        else
        {
            // nothing
        }
    }
    return ue_spec_config;
    trackinglock.unlock();
}

void MCSTracking::update_default_ue_config(ltesniffer_ue_spec_config_t ue_spec_config)
{
    std::unique_lock<std::mutex> trackinglock(tracking_mutex);
    // printf("[CONFIG] Set default UE-specific configuration: P_a = %.2f, UCI Config: %d %d %d, CQI Config: %d\n",
    //                                                                 ue_spec_config.p_a,
    //                                                                 ue_spec_config.uci_config.I_offset_ack,
    //                                                                 ue_spec_config.uci_config.I_offset_cqi,
    //                                                                 ue_spec_config.uci_config.I_offset_ri,
    //                                                                 ue_spec_config.cqi_config.type);
    default_ue_spec_config = ue_spec_config;
    trackinglock.unlock();
}

void MCSTracking::set_default_of_default_config()
{
    std::unique_lock<std::mutex> trackinglock(tracking_mutex);
    default_ue_spec_config.uci_config.I_offset_ack = 10; // KT
    default_ue_spec_config.uci_config.I_offset_cqi = 8;
    default_ue_spec_config.uci_config.I_offset_ri = 11;
    default_ue_spec_config.p_a = 0;
    default_ue_spec_config.cqi_config.type = SRSRAN_CQI_TYPE_SUBBAND_HL;
    trackinglock.unlock();
}