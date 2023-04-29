#pragma once

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

/*Print color to terminal*/
#define RESET       "\033[0m"
#define BLACK       "\033[30m"              /* Black */
#define RED         "\033[31m"              /* Red */
#define GREEN       "\033[32m"              /* Green */
#define YELLOW      "\033[33m"              /* Yellow */
#define BLUE        "\033[34m"              /* Blue */
#define MAGENTA     "\033[35m"              /* Magenta */
#define CYAN        "\033[36m"              /* Cyan */
#define WHITE       "\033[37m"              /* White */
#define BOLDBLACK   "\033[1m\033[30m"      /* Bold Black */
#define BOLDRED     "\033[1m\033[31m"      /* Bold Red */
#define BOLDGREEN   "\033[1m\033[32m"      /* Bold Green */
#define BOLDYELLOW  "\033[1m\033[33m"      /* Bold Yellow */
#define BOLDBLUE    "\033[1m\033[34m"      /* Bold Blue */
#define BOLDMAGENTA "\033[1m\033[35m"      /* Bold Magenta */
#define BOLDCYAN    "\033[1m\033[36m"      /* Bold Cyan */
#define BOLDWHITE   "\033[1m\033[37m"      /* Bold White */

#define DL_MODE     0
#define UL_MODE     1

#define ID_RAN_VAL  0
#define ID_TMSI     1
#define ID_CON_RES  2
#define ID_IMSI     3
#define ID_IMEI     4
#define ID_IMEISV   5

#define MSG_CON_REQ 0
#define MSG_CON_SET 1
#define MSG_ATT_REQ 2
#define MSG_ID_RES  3
#define MSG_UE_CAP  4
#define MSG_PAGING  5

struct DCI_BASE {
    DCI_BASE();
    uint16_t rnti;
    srsran_dci_format_t format;
    uint32_t nof_bits;
    std::string hex;
    srsran_dci_location_t location;
    uint32_t histval;
    bool check = false;
};

struct DCI_DL : public DCI_BASE {
    DCI_DL();
    std::unique_ptr<srsran_ra_dl_dci_t> dl_dci_unpacked;
    std::unique_ptr<srsran_ra_dl_grant_t> dl_grant;
    
};

struct DCI_UL : public DCI_BASE {
	DCI_UL();
	//DCI_UL operator=(const DCI_UL& dci_ul);
	std::shared_ptr<srsran_ra_ul_dci_t>     ul_dci_unpacked;
	std::shared_ptr<srsran_ra_ul_grant_t>   ul_grant;
	std::shared_ptr<srsran_dci_ul_t>        ran_ul_dci;
	std::shared_ptr<srsran_pusch_grant_t>   ran_ul_grant;     //for UL 64QAM table
    std::shared_ptr<srsran_pusch_grant_t>   ran_ul_grant_256; //for UL 256QAM table
	int decoded = 0;
	int is_retx = 0;
    int is_rar_gant = 0;
    ul_sniffer_mod_tracking_t mcs_mod = UL_SNIFFER_UNKNOWN_MOD;
    int nof_ack = 0;
};

struct  DL_Sniffer_DCI_DL: public DCI_BASE {
    DL_Sniffer_DCI_DL();
    dl_sniffer_mcs_table_t                  mcs_table;
    std::shared_ptr<srsran_dci_dl_t>        ran_dci_dl;
    std::shared_ptr<srsran_pdsch_grant_t>   ran_pdsch_grant;
    std::shared_ptr<srsran_pdsch_grant_t>   ran_pdsch_grant_256;
};
