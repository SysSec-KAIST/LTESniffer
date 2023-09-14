#pragma once
#include "DCICollection.h"
#include "PcapWriter.h"
#include "ULSchedule.h"
#include "SubframePower.h"
#include "MCSTracking.h"
#include "Sniffer_dependency.h"
#include "srsran/phy/common/phy_common.h"
#include "srsran/interfaces/ue_interfaces.h"
#include "srsran/asn1/rrc/ul_ccch_msg.h"
#include "srsran/asn1/rrc/ul_dcch_msg.h"
#include "srsran/rlc/rlc_common.h"
#include "srsran/rlc/rlc_am_lte.h"
#include "srsran/asn1/liblte_common.h"
#include "srsran/asn1/liblte_mme.h"
#include "srsran/asn1/s1ap.h"
#include "srsran/mac/pdu.h"
#include <sstream>

using namespace asn1;
using namespace asn1::s1ap;
using namespace rrc;

#include <iostream>
#include <fstream>

// include C-only headers
#ifdef __cplusplus
    extern "C" {
#endif

#include "srsran/phy/phch/pusch_cfg.h"
#include "srsran/phy/enb/enb_ul.h"
#include "srsran/phy/ue/ue_ul.h"
#include "falcon/phy/falcon_phch/dl_sniffer_pdsch.h"

#ifdef __cplusplus
}
#undef I // Fix complex.h #define I nastiness when using C++
#endif

const static int prach_buffer_sz = 128 * 1024;

class PUSCH_Decoder
{
public:
    PUSCH_Decoder(srsran_enb_ul_t &enb_ul,
                  srsran_ul_sf_cfg_t &ul_sf,
                  ULSchedule *ulsche,
                  cf_t** original_buffer,
                  cf_t** buffer_offset,
                  srsran_ul_cfg_t    &ul_cfg,
                  LTESniffer_pcap_writer *pcapwriter,
                  MCSTracking *mcstracking,
                  bool en_debug);
    ~PUSCH_Decoder();

    void init_pusch_decoder(std::vector<DCI_UL>* dci_ul,
                            std::vector<DCI_UL>* rar_dci_ul,
                            srsran_ul_sf_cfg_t &ul_sf,
                            SubframePower* sf_power);
    void decode();

    int  decode_rrc_connection_request(DCI_UL &decoding_mem, uint8_t* sdu_ptr, int length);
    int  decode_ul_dcch(DCI_UL &decoding_mem, uint8_t* sdu_ptr, int length);
    int  decode_nas_ul(DCI_UL &decoding_mem, uint8_t* sdu_ptr, int length);
    // void decode_IMSI_attach(DCI_UL &decoding_mem, uint8_t* sdu_ptr, int length);
    
    /*Investigate UL grant before decoding it*/
    int  check_valid_prb_ul(uint32_t nof_prb);
    int  investigate_valid_ul_grant(DCI_UL &decoding_mem);

    void decode_run(std::string info, DCI_UL &decoding_mem, std::string mod, float falcon_signal_power);

    void set_configed() { configed = true;}
    bool get_configed() { return configed;}

    std::string modulation_mode_string(int mode, bool max_64qam);
    std::string modulation_mode_string_256(int idx);
    void print_debug(DCI_UL &decoding_mem, 
                     std::string offset_name, 
                     std::string modulation_mode,
                     float signal_pw,
                     double noise,
                     double falcon_sgl_pwr);
    void print_ul_grant(srsran_pusch_grant_t& grant);
    void print_uci(srsran_uci_value_t *uci);
    void print_success(DCI_UL &decoding_mem, std::string offset_name, int table);
    void print_api(uint32_t tti, uint16_t rnti, int ident, std::string value, int msg);

    void set_rach_config(srsran_prach_cfg_t prach_cfg_);

    void work_prach(); 

    void set_ul_harq (UL_HARQ *ul_harq_) { ul_harq = ul_harq_;  }
    void set_target_rnti(uint16_t rnti)  { target_rnti = rnti;  }
    void set_debug_mode(bool en_debug_)  { en_debug = en_debug_;}
    void set_api_mode(int api_mode_)     { api_mode = api_mode_;}
private:
    uint16_t target_rnti    = -1;
    bool en_debug           = false;
    int api_mode            = -1;
    bool configed           = false;
    ULSchedule              *ulsche;
    cf_t                    **original_buffer   = {nullptr};
    cf_t                    ** buffer_offset    = {nullptr};
    SubframePower           *sf_power;

    std::vector<DCI_UL>     *dci_ul;
    std::vector<DCI_UL>     *rar_dci_ul;
    int                     valid_ul_grant      = SRSRAN_ERROR;

    srsran_enb_ul_t         &enb_ul;
    srsran_ul_sf_cfg_t      &ul_sf;
    LTESniffer_pcap_writer  *pcapwriter;
    srsran_pusch_res_t      pusch_res           = {};
    srsran_ul_cfg_t         &ul_cfg;

    /*variables for prach*/
    srsran_prach_cfg_t      prach_cfg           = {};
    srsran_prach_t          prach               = {};
    uint32_t                prach_indices[165]  = {};
    float                   prach_offsets[165]  = {};
    float                   prach_p2avg[165]    = {};
    uint32_t                nof_sf = 0;
    cf_t                    samples[prach_buffer_sz] = {};
    UL_HARQ                 *ul_harq; //on developing
    MCSTracking             *mcstracking;

    /*Backup*/
    int                     multi_ul_offset;
};


