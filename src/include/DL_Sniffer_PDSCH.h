#pragma once

#include "DCICollection.h"
#include "PhyCommon.h"
#include <vector>
#include <sstream>
#include "PcapWriter.h"
#include "HARQ.h"
#include "srsran/mac/pdu.h"
#include "srsue/hdr/stack/mac/proc_ra.h"
#include "srsran/asn1/rrc/dl_ccch_msg.h"
#include "srsran/asn1/rrc/dl_dcch_msg.h"
#include "srsran/asn1/asn1_utils.h"
#include "srsran/asn1/liblte_mme.h"
#include "srsran/asn1/rrc/paging.h"
// #include "srsran/asn1/rrc/dl_dcch_msg.h"

// include C-only headers
#ifdef __cplusplus
    extern "C" {
#endif

#include "falcon/phy/falcon_phch/dl_sniffer_pdsch.h"
#include "falcon/phy/falcon_phch/ul_sniffer_pusch.h"
#include "srsran/phy/phch/ra_ul.h"
#include "falcon/phy/falcon_ue/falcon_ue_dl.h"
#include "srsran/phy/fec/softbuffer.h"
#include "srsran/phy/phch/dci.h"

#ifdef __cplusplus
}
#undef I // Fix complex.h #define I nastiness when using C++
#endif

#define DL_SNIFFER_SIB2_SUCCESS 3
#define UL_SNIFFER_FOUND_CON_SET 4

/*include for decode SIB2*/
#include "srsran/asn1/rrc/bcch_msg.h"
#include "srsran/asn1/asn1_utils.h"
#include "srsran/asn1/rrc/common.h"
#include "srsran/asn1/rrc_utils.h"
#include "srsran/rrc/rrc_common.h"
#include "srsran/asn1/rrc/si.h"
#include "srsran/asn1/rrc/rr_common.h"

/*Include for decode MAC CE*/
#include "srsran/mac/pdu.h"


using namespace asn1;
using namespace asn1::rrc;


const uint32_t RAR_GRANT_LENGTH = 20;
struct DL_Sniffer_rar_result
{
    uint16_t t_crnti = 0;
    int ta = 0;
    uint8_t grant[RAR_GRANT_LENGTH];
    srsran_dci_ul_t ran_dci_ul = {};
    srsran_pusch_grant_t ran_ul_grant = {};
};

enum PDUDecodingResult_t {
    pdu_rrc_con_set = 0,
    pdu_rrc_con_request = 1,
    pdu_rrc_con_reconfig = 2,
    pdu_unknown = 3
};

struct DL_Sniffer_PDU_info_t
{
    PDUDecodingResult_t pdu_type = pdu_unknown;
    uint32_t tmsi = 0;
};

class PDSCH_Decoder
{
public:
    PDSCH_Decoder(uint32_t idx, 
                  LTESniffer_pcap_writer *pcapwriter, 
                  std::vector<LTESniffer_stat_writer *> *filewriter_objs,
                  MCSTracking *mcs_tracking,
                  RNTIManager& rntiManager,
                  HARQ *harq,
                  int mcs_tracking_mode,
                  int harq_mode,
                  int nof_antenna);

    PDSCH_Decoder(uint32_t idx,
                  falcon_ue_dl_t &falcon_ue_dl,
                  srsran_dl_sf_cfg_t &dl_sf,
                  srsran_ue_dl_cfg_t &ue_dl_cfg,
                  std::vector<DL_Sniffer_DCI_DL> &ran_dl_collection,
                  uint32_t sfn,
                  uint32_t sf_idx,
                  LTESniffer_pcap_writer *pcapwriter,
                  srsran_pdsch_res_t *pdsch_res,
                  srsran_pdsch_cfg_t *pdsch_cfg);

    ~PDSCH_Decoder();

    int init_pdsch_decoder(falcon_ue_dl_t *falcon_ue_dl,
                           srsran_dl_sf_cfg_t *dl_sf,
                           srsran_ue_dl_cfg_t *ue_dl_cfg,
                           std::vector<DL_Sniffer_DCI_DL> *ran_dl_collection,
                           uint32_t sfn,
                           uint32_t sf_idx);
    void unpack_pdsch_message(uint8_t* sdu_ptr, int length);
    int  decode_rrc_connection_setup(uint8_t* sdu_ptr, int length, ltesniffer_ue_spec_config_t *ue_config);
    int  decode_rrc_connection_reconfig(uint8_t *sdu_ptr, int length, DL_Sniffer_PDU_info_t &pdu_info, int tti_tx_dl);                    
    int  decode_imsi_tmsi_paging(uint8_t* sdu_ptr, int length);

    void run_api_dl_mode(std::string RNTI_name, 
                        uint8_t *pdu, 
                        uint32_t 
                        pdu_len_bytes, 
                        uint16_t crnti, 
                        uint32_t tti, 
                        int tb);
    
    int  run_decode(int &mimo_ret,
                    srsran_dci_format_t cur_format,
                    srsran_dci_dl_t *cur_ran_dci_dl,
                    srsran_pdsch_grant_t *cur_grant,
                    uint32_t cur_rnti,
                    std::string table, 
                    std::string rnti_name,
                    uint32_t tti);
    int decode_SIB();
    int decode_dl_mode();

    int decode_mac_ce(uint32_t rnti);

    int decode_ul_mode(uint32_t rnti, std::vector<DL_Sniffer_rar_result> *rar_result);
    
    asn1::rrc::sib_type2_s* getSIB2(){ return &sib2; }

    void write_pcap(std::string RNTI_name, uint8_t *pdu, uint32_t pdu_len_bytes, uint16_t crnti, uint32_t tti, bool retx);

    void unpack_rar_response_dl_mode(uint8_t *ptr, int result_length); //check rar time of crnti to track MCS table
    int  run_rar_decode(srsran_dci_format_t cur_format,
                        srsran_dci_dl_t *cur_ran_dci_dl,
                        srsran_pdsch_grant_t *cur_grant,
                        uint32_t cur_rnti,
                        DL_Sniffer_rar_result &result);
    int decode_rar(DL_Sniffer_rar_result &result);
    int unpack_rar_response_ul_mode(uint8_t *payload, int length, DL_Sniffer_rar_result &result);

    void set_hopping(srsran_pusch_hopping_cfg_t hopping_cfg_)
    {
        hopping_cfg = hopping_cfg_;
    }

    asn1::rrc::rrc_conn_setup_r8_ies_s get_rrc_con_set() {return rrc_con_set;}
    ltesniffer_ue_spec_config_t        get_default_ue_config() {return default_ue_spec_config;}
    
    std::string dci_format(int format);
    std::string mod_sche(int sche);
    std::string rnti_name(uint16_t rnti);
    /* print physical channel information */
    void print_debug_dl(std::string name,
                        int tti,
                        uint16_t rnti,
                        std::string format,
                        std::string mod,
                        int table,
                        int retx,
                        int nof_tb,
                        int length,
                        bool result,
                        srsran_chest_dl_res_t* ce_res);
    void set_target_rnti(uint16_t rnti) {
        if (rnti != 0){
            has_target_rnti = true;
            target_rnti = rnti;
        }
    }
    void set_debug_mode(bool debug) { en_debug = debug;}
    void set_api_mode(int api_mode_) { api_mode = api_mode_;}
    void print_api_dl(uint32_t tti, uint16_t rnti, int ident, std::string value, int msg, uint32_t ta_rnti);

private:
    int         api_mode            = -1; 
    bool        en_debug            = false;
    uint16_t    target_rnti         = 0;
    bool        has_target_rnti     = false;
    int         nof_antenna         = 2;
    /*RRC Con Set*/
    bool                               found_con_ret = false;
    asn1::rrc::rrc_conn_setup_r8_ies_s rrc_con_set;
    bool                               has_default_config = false;
    ltesniffer_ue_spec_config_t        default_ue_spec_config = {};
    /*Index of worker and subframe timing*/
    uint32_t idx; 
    uint32_t sf_idx;
    uint32_t sfn;

    srsran_softbuffer_rx_t          *buffer[SRSRAN_MAX_CODEWORDS];
    falcon_ue_dl_t                  *falcon_ue_dl;   //cell inside q
    srsran_dl_sf_cfg_t              *dl_sf;      //cfi not
    srsran_ue_dl_cfg_t              *ue_dl_cfg;  //cfg->dci cfg
    std::vector<DL_Sniffer_DCI_DL>  *ran_dl_collection;
    srsran_pdsch_res_t              *pdsch_res;
    srsran_pdsch_cfg_t              *pdsch_cfg; //buffer
    LTESniffer_pcap_writer          *pcapwriter;
    std::vector<LTESniffer_stat_writer *> *filewriter_objs;
    RNTIManager                     &rntiManager;
    int                             mcs_tracking_mode;
    MCSTracking                     *mcs_tracking;
    int                             harq_mode;
    HARQ                            *harq;

    /*SIB2 for uplink config*/
    asn1::rrc::sib_type2_s sib2;

    /*Conver grant in rar*/
    srsran_pusch_hopping_cfg_t      hopping_cfg = {};
};

