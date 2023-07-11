#pragma once

#include "map"
#include "mutex"
#include "memory"
#include "include/DCICollection.h"
#include "srsran/asn1/rrc/bcch_msg.h"
#include "srsran/asn1/rrc/dl_ccch_msg.h"
#include <iostream>
#include <fstream>
#include <ctime>
#include <srsran/common/mac_pcap.h>
#include "HARQ.h"

#ifdef __cplusplus
    extern "C" {
#endif
#include "srsran/phy/ch_estimation/refsignal_ul.h"
#include "srsran/phy/phch/prach.h"
#ifdef __cplusplus
}
#undef I // Fix complex.h #define I nastiness when using C++
#endif

#define UL_SNIFFER_NOF_AVERAGE 100
#define UL_SNIFFER_NOF_PRINT 20
#define UL_SNIFFER_INACTIVE_TIMER 3
#define UL_SNIFFER_SNR_THRES 5


#define URESET       "\033[0m"
#define UBLACK       "\033[30m"              /* Black */
#define URED         "\033[31m"              /* Red */
#define UGREEN       "\033[32m"              /* Green */
#define UYELLOW      "\033[33m"              /* Yellow */
#define UBLUE        "\033[34m"              /* Blue */
#define UMAGENTA     "\033[35m"              /* Magenta */
#define UCYAN        "\033[36m"              /* Cyan */
#define UWHITE       "\033[37m"              /* White */
#define UBOLDBLACK   "\033[1m\033[30m"      /* Bold Black */
#define UBOLDRED     "\033[1m\033[31m"      /* Bold Red */
#define UBOLDGREEN   "\033[1m\033[32m"      /* Bold Green */
#define UBOLDYELLOW  "\033[1m\033[33m"      /* Bold Yellow */
#define UBOLDBLUE    "\033[1m\033[34m"      /* Bold Blue */
#define UBOLDMAGENTA "\033[1m\033[35m"      /* Bold Magenta */
#define UBOLDCYAN    "\033[1m\033[36m"      /* Bold Cyan */
#define UBOLDWHITE   "\033[1m\033[37m"      /* Bold White */

struct DCI_UL;

typedef struct {
    std::vector<float> arvl_time_database;
    std::vector<float> arvl_time_success_database;
    std::vector<float> arvl_time_failed_database;
    std::vector<float> arvl_time_h_snr_database;
    std::vector<float> arvl_time_l_snr_database;
    /*Container of average time for each 100 msg*/
    std::vector<float> avg_database;
    std::vector<float> avg_success_database;
    std::vector<float> avg_failed_database;
    std::vector<float> avg_h_snr_database;
    std::vector<float> avg_l_snr_database;
} UL_Sniffer_arrival_time_t;

class ULSchedule
{
public:
    ULSchedule(uint32_t rnti, UL_HARQ *ul_harq, bool en_debug);
    ~ULSchedule();

    void                 pushULSche(uint32_t tti, const std::vector<DCI_UL>& dci_ul);
    void                 push_rar_ULSche(uint32_t tti, const std::vector<DCI_UL>& rar_dci_ul);
    void                 deleteULSche(uint32_t tti);
    void                 delete_rar_ULSche(uint32_t tti);
    std::vector<DCI_UL>* getULSche(uint32_t tti);
    std::vector<DCI_UL>* get_rar_ULSche(uint32_t tti);
    int                  get_ul_tti(uint32_t cur_tti);
    int                  get_rar_ul_tti(uint32_t cur_tti);

    void                 set_config();
    bool                 get_config()                    {return  config;   }
    bool                 check_rrc_con_set()             {return  has_rrc_con_set;}
    bool                 get_debug_mode()                { return en_debug; }
    uint32_t             get_rnti()                      { return rnti;     }
    bool                 get_multi_ul_offset_cfg()       { return multi_ul_offset;}
    void                 set_multi_offset(int enable)    { multi_ul_offset = enable;}
    srsran_prach_cfg_t   get_prach_config()              { return prach_cfg;}
    srsran_refsignal_dmrs_pusch_cfg_t   get_dmrs();
    asn1::rrc::rrc_conn_setup_r8_ies_s  get_rrc_con_set(){return rrc_con_set;}
    void                 set_SIB2(asn1::rrc::sib_type2_s* sib2);
    void                 clean_database(std::map<uint32_t, UL_Sniffer_arrival_time_t>::iterator iter);
    void                 set_rrc_con_set(asn1::rrc::rrc_conn_setup_r8_ies_s rrc_con_set_);
    asn1::rrc::sib_type2_s sib2; //public access
private:
    uint32_t            rnti            = 0; //-R
    bool                en_debug        = false;
    bool                config          = false;
    bool                print_get_config= true;
    std::mutex          ulsche_mutex;
    int                 multi_ul_offset = 0;
    bool                has_rrc_con_set = false;
    srsran_prach_cfg_t  prach_cfg = {};
    srsran_refsignal_dmrs_pusch_cfg_t               dmrs_cfg = {};
    std::map<uint32_t, std::vector<DCI_UL>>         ulsche_database;
    std::map<uint32_t, std::vector<DCI_UL>>         ulsche_rar_database;
    std::map<uint32_t, UL_Sniffer_arrival_time_t>   arvl_time_database;
    asn1::rrc::rrc_conn_setup_r8_ies_s              rrc_con_set; //RRC Connect Setup for getting config
};
