#pragma once

//#include "DCICollection.h"
#include "Sniffer_dependency.h"
#include "map"
#include "mutex"
#include "memory"
#include <ctime>
#include <vector>
#include "HARQ.h"
#include <stdio.h>
#include <iostream>
#include <fstream>
#include <iomanip>
#include <map>
#include <atomic>

// include C-only headers
#ifdef __cplusplus
    extern "C" {
#endif

#include "falcon/phy/falcon_phch/falcon_dci.h"

#ifdef __cplusplus
}
#undef I // Fix complex.h #define I nastiness when using C++
#endif

#define DL_SNIFFER_MCSTRACKING_MAX_SIZE 250
#define DL_SNIFFER_MCS_MODE_OFF 0
#define DL_SNIFFER_MCS_MODE_ON 1
#define DL_SNIFFER_MCS_MODE_BOTH 2

#define DL_SNIFFER_NOF_MCS 32

typedef struct SRSRAN_API
{
    bool                        has_ue_config = false;
    float                       p_a           = 0; // downlink pdsch power allocation from RRC Con Set
    srsran_uci_offset_cfg_t     uci_config    = {0};
    srsran_cqi_cfg_t            cqi_config    = {0};
} ltesniffer_ue_spec_config_t;


typedef struct SRSRAN_API
{
    clock_t  time                   = 0;
    uint16_t nof_msg_after_rar      = 0; // number of PDSCH messages with DCI > 1A after rar
    bool     has_rar = false;
    bool     to_all_database        = true;
    uint32_t nof_active             = 0; //
    uint32_t nof_newtx              = 0; //
    uint32_t nof_success_mgs        = 0; //
    uint32_t nof_retx               = 0; //
    uint32_t nof_success_retx_nom   = 0; //
    uint32_t nof_success_retx_harq  = 0; //
    uint32_t nof_success_retx       = 0;
    uint32_t nof_unsupport_mimo     = 0;
    uint32_t nof_pinfo              = 0;
    uint32_t nof_other_mimo         = 0;
    uint32_t mcs[DL_SNIFFER_NOF_MCS] = {0};
    uint32_t mcs_sc[DL_SNIFFER_NOF_MCS] ={0};
    dl_sniffer_mcs_table_t      mcs_table = DL_SNIFFER_UNKNOWN_TABLE;
    bool                        has_ue_config = false;
    ltesniffer_ue_spec_config_t ue_spec_config;
} dl_sniffer_mcs_tracking_t;

typedef struct SRSRAN_API
{
    clock_t  time                   = 0;
    bool     to_all_database        = true;
    uint32_t nof_active             = 0; //
    uint32_t nof_newtx              = 0; //
    uint32_t nof_success_mgs        = 0; //
    uint32_t nof_retx               = 0; //
    uint32_t nof_success_retx_nom   = 0; //
    uint32_t nof_success_retx_harq  = 0; //
    uint32_t nof_success_retx       = 0;
    uint32_t nof_unsupport_mimo     = 0;
    uint32_t nof_pinfo              = 0;
    uint32_t nof_other_mimo         = 0;
    uint32_t mcs[DL_SNIFFER_NOF_MCS] = {0};
    uint32_t mcs_sc[DL_SNIFFER_NOF_MCS] ={0};
    ul_sniffer_mod_tracking_t   mcs_mod = UL_SNIFFER_UNKNOWN_MOD;
    bool                        has_ue_config = false;
    ltesniffer_ue_spec_config_t ue_spec_config;
    std::vector<float>          snr;
    std::vector<float>          ta;
} ul_sniffer_tracking_t;


class MCSTracking
{
public:
    MCSTracking(int tracking_mode, 
                uint16_t target_rnti, 
                bool en_debug, 
                int sniffer_mode, 
                int apt_mode,
                std::atomic<float> &est_cfo);
    ~MCSTracking();

    /*UL 256/64QAM/16QAM tracking implementation*/
    ul_sniffer_mod_tracking_t find_tracking_info_RNTI_ul(uint16_t RNTI);
    int  add_RNTI_ul(uint16_t RNTI, ul_sniffer_mod_tracking_t mcs_mod);
    void update_RNTI_ul(uint16_t RNTI, ul_sniffer_mod_tracking_t mcs_mod);
    void update_database_ul();
    int  nof_RNTI_member_ul(){ return tracking_database_ul_mode.size();}
    void print_database_ul();
    void merge_all_database_ul();
    void print_all_database_ul();
    void update_statistic_ul(uint16_t RNTI, bool success, DCI_UL &decoding_mem, float snr, float ta);

    /*DL 256QAM/64QAM tracking implementation*/
    dl_sniffer_mcs_table_t find_tracking_info_RNTI_dl(uint16_t RNTI);
    int  add_RNTI_dl(uint16_t RNTI, dl_sniffer_mcs_table_t mcs_table);
    void update_RNTI_dl(uint16_t RNTI, dl_sniffer_mcs_table_t mcs_table);
    void update_database_dl();
    int  nof_RNTI_member_dl(){ return tracking_database_dl_mode.size();}
    void print_database_dl();
    void merge_all_database_dl();
    void print_all_database_dl();
    void update_rar_time_crnti(uint16_t crnti, clock_t cur_time);
    void update_statistic_dl(uint16_t RNTI,
                            bool tb_en[SRSRAN_MAX_CODEWORDS],
                            int transmission_type[SRSRAN_MAX_CODEWORDS],
                            bool success[SRSRAN_MAX_CODEWORDS],
                            DL_Sniffer_DCI_DL &decoding_mem,
                            int mimo_ret,
                            srsran_pdsch_grant_t *statistic_grant);
    
    /*Manage UE-specific-configuration*/
    void                        update_ue_config_rnti(uint16_t rnti, ltesniffer_ue_spec_config_t ue_spec_config);
    ltesniffer_ue_spec_config_t get_ue_config_rnti(uint16_t rnti);
    void                        update_default_ue_config(ltesniffer_ue_spec_config_t ue_spec_config);
    
    double      get_interval() { return interval;}
    uint16_t    get_target_rnti(){ return target_rnti;}
    void        set_debug_mode(bool en_debug_) { en_debug = en_debug_;}
    bool        get_debug_mode();
    void        write_csv_file(uint16_t rnti, dl_sniffer_mcs_tracking_t &statistic, int table);
    int         get_sniffer_mode(){ return sniffer_mode;}
    int         get_api_mode(){return api_mode;}
    bool        check_default_config(){ return has_default_ue_spec_config;}
    void        set_has_default_config(){ has_default_ue_spec_config = true;}
    void        set_default_of_default_config();
    int         get_nof_api_msg(){ return nof_api_msg;}
    void        increase_nof_api_msg(){ nof_api_msg++;}
    void        reset_nof_api_msg(){ nof_api_msg = 1;}
    std::atomic<float>& get_est_cfo(){return est_cfo;}
    clock_t     last_check;

private:
    int         sniffer_mode    = DL_MODE;
    int         harq_mode       = 0;
    int         api_mode        = -1;
    int         tracking_mode   = DL_SNIFFER_MCS_MODE_ON;
    bool        en_debug        = false;
    uint16_t    target_rnti     = 0;
    int         max_size        = DL_SNIFFER_MCSTRACKING_MAX_SIZE;
    long double interval        = 5.0;   // 5 secs
    uint16_t    rar_thresold    = 3; // number of messages with DCI > 1A after rar response
    std::mutex  tracking_mutex;
    // std::mutex  config_mutex;
    bool        has_default_ue_spec_config        = false;
    std::atomic<float>                            &est_cfo;
    std::atomic<int>                              nof_api_msg{0};
    ltesniffer_ue_spec_config_t                   default_ue_spec_config = {};
    std::map<uint16_t, ul_sniffer_tracking_t>     tracking_database_ul_mode;
    std::map<uint16_t, ul_sniffer_tracking_t>     all_database_ul_mode;
    std::map<uint16_t, dl_sniffer_mcs_tracking_t> tracking_database_dl_mode;
    std::map<uint16_t, dl_sniffer_mcs_tracking_t> all_database_dl_mode;
    /*Statistic file*/
    std::ofstream   csv_file;
    std::string     file_name = "mcs_statistic.csv";
};