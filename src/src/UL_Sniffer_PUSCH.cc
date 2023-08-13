#include "include/UL_Sniffer_PUSCH.h"

bool valid_prb_ul[101] = {true, true, true, true, true, true, true, false, true, true, true, false, true,
                          false, false, true, true, false, true, false, true, false, false, false, true, true,
                          false, true, false, false, true, false, true, false, false, false, true, false, false,
                          false, true, false, false, false, false, true, false, false, true, false, true, false,
                          false, false, true, false, false, false, false, false, true, false, false, false, true,
                          false, false, false, false, false, false, false, true, false, false, true, false, false,
                          false, false, true, true, false, false, false, false, false, false, false, false, true,
                          false, false, false, false, false, true, false, false, false, true};

PUSCH_Decoder::PUSCH_Decoder(srsran_enb_ul_t &enb_ul,
                             srsran_ul_sf_cfg_t &ul_sf,
                             ULSchedule *ulsche,
                             cf_t **original_buffer,
                             cf_t **buffer_offset,
                             srsran_ul_cfg_t &ul_cfg,
                             LTESniffer_pcap_writer *pcapwriter,
                             MCSTracking *mcstracking,
                             bool en_debug) : enb_ul(enb_ul),
                                              ul_sf(ul_sf),
                                              dci_ul(),
                                              ulsche(ulsche),
                                              original_buffer(original_buffer),
                                              buffer_offset(buffer_offset),
                                              ul_cfg(ul_cfg),
                                              pcapwriter(pcapwriter),
                                              sf_power(),
                                              mcstracking(mcstracking),
                                              en_debug(en_debug)
{
    set_target_rnti(ulsche->get_rnti());
    set_debug_mode(ulsche->get_debug_mode());
    set_api_mode(mcstracking->get_api_mode());
    multi_ul_offset = ulsche->get_multi_ul_offset_cfg();
    pusch_res.data = srsran_vec_u8_malloc(2000 * 8);
    ul_cfg.pusch.softbuffers.rx = new srsran_softbuffer_rx_t;
    srsran_softbuffer_rx_init(ul_cfg.pusch.softbuffers.rx, SRSRAN_MAX_PRB);
}

PUSCH_Decoder::~PUSCH_Decoder()
{
    srsran_vec_u8_zero(pusch_res.data, 2000 * 8);
    srsran_softbuffer_rx_free(ul_cfg.pusch.softbuffers.rx);
}

int PUSCH_Decoder::decode_rrc_connection_request(DCI_UL &decoding_mem, uint8_t *sdu_ptr, int length)
{
    int ret = SRSRAN_ERROR;
    ul_ccch_msg_s ul_ccch_msg;
    asn1::cbit_ref bref(sdu_ptr, length);
    int asn1_result = ul_ccch_msg.unpack(bref);
    if (asn1_result == asn1::SRSASN_SUCCESS && ul_ccch_msg.msg.type() == ul_ccch_msg_type_c::types_opts::c1)
    {
        if (ul_ccch_msg.msg.c1().type().value == ul_ccch_msg_type_c::c1_c_::types::rrc_conn_request)
        {
            asn1::rrc::rrc_conn_request_s con_request = ul_ccch_msg.msg.c1().rrc_conn_request();
            rrc_conn_request_r8_ies_s *msg_r8 = &con_request.crit_exts.rrc_conn_request_r8();
            if (msg_r8->ue_id.type() == init_ue_id_c::types::s_tmsi)
            {
                uint32_t m_tmsi = msg_r8->ue_id.s_tmsi().m_tmsi.to_number();
                uint8_t mmec = msg_r8->ue_id.s_tmsi().mmec.to_number();
                std::stringstream ss;
                ss << std::hex << m_tmsi;
                std::string m_tmsi_str = ss.str();
                print_api(ul_sf.tti, decoding_mem.rnti, ID_TMSI, m_tmsi_str, MSG_CON_REQ);
                mcstracking->increase_nof_api_msg();
                ret = SRSRAN_SUCCESS;
            }
            else if (msg_r8->ue_id.type() == init_ue_id_c::types::random_value)
            {
                std::string rd_value_bitstream = msg_r8->ue_id.random_value().to_string();
                std::stringstream ss;
                for (int i = 0; i < rd_value_bitstream.length(); i += 4)
                {
                    std::string hex_str = rd_value_bitstream.substr(i, 4);
                    int hex_value = stoi(hex_str, nullptr, 2);
                    ss << std::hex << hex_value;
                }
                std::string random_value_str = ss.str();
                random_value_str = random_value_str.substr(2);
                print_api(ul_sf.tti, decoding_mem.rnti, ID_RAN_VAL, random_value_str, MSG_CON_REQ);
                mcstracking->increase_nof_api_msg();
                ret = SRSRAN_SUCCESS;
            }
        }
        else if (ul_ccch_msg.msg.c1().type().value == ul_ccch_msg_type_c::c1_c_::types::rrc_conn_reest_request)
        {
            // Do nothing
        }
    }
    return ret;
}

/*UEcapability information or RRC Connection Setup Complete + Attach request*/
int PUSCH_Decoder::decode_ul_dcch(DCI_UL &decoding_mem, uint8_t *sdu_ptr, int length)
{
    int ret = SRSRAN_ERROR;
    ul_dcch_msg_s ul_dcch_msg;
    asn1::cbit_ref bref(sdu_ptr, length);
    int asn1_result = ul_dcch_msg.unpack(bref);
    if (asn1_result == asn1::SRSASN_SUCCESS && ul_dcch_msg.msg.type() == ul_dcch_msg_type_c::types_opts::c1)
    {
        if (ul_dcch_msg.msg.c1().type() == ul_dcch_msg_type_c::c1_c_::types::ue_cap_info && (api_mode == 1 || api_mode == 3))
        { //&& UECapability
            // printf("[API] SF: %d-%d, RNTI: %d, Found UECapabilityInformation messages \n", ul_sf.tti/10, ul_sf.tti%10, decoding_mem.rnti);
            print_api(ul_sf.tti, decoding_mem.rnti, -1, "-", MSG_UE_CAP);
            mcstracking->increase_nof_api_msg();
            ret = SRSRAN_SUCCESS;
        }
        else if (ul_dcch_msg.msg.c1().type() == ul_dcch_msg_type_c::c1_c_::types::rrc_conn_setup_complete && (api_mode == 2 || api_mode == 3))
        { // IMSI catching, IMSI attach
            // printf("[API] SF: %d-%d, RNTI: %d, Found RRC Connection Setup Complete \n", ul_sf.tti/10, ul_sf.tti%10, decoding_mem.rnti);
            asn1::rrc::rrc_conn_setup_complete_s msg = ul_dcch_msg.msg.c1().rrc_conn_setup_complete();
            rrc_conn_setup_complete_r8_ies_s *msg_r8 = &msg.crit_exts.c1().rrc_conn_setup_complete_r8();
            srsran::unique_byte_buffer_t nas_msg = srsran::make_byte_buffer();
            nas_msg->N_bytes = msg_r8->ded_info_nas.size();
            memcpy(nas_msg->msg, msg_r8->ded_info_nas.data(), nas_msg->N_bytes);
            // parse nas_msg inside rrc connection setup complete to nas decoder
            ret = decode_nas_ul(decoding_mem, nas_msg->msg, nas_msg->N_bytes);
        }
        else if (ul_dcch_msg.msg.c1().type() == ul_dcch_msg_type_c::c1_c_::types::ul_info_transfer && (api_mode == 2 || api_mode == 3))
        { // IMSI catching, Identity response
            // printf("[API] SF: %d-%d, RNTI: %d, Found UL Infor Transfer \n", ul_sf.tti/10, ul_sf.tti%10, decoding_mem.rnti);
            srsran::unique_byte_buffer_t nas_msg = srsran::make_byte_buffer();
            nas_msg->N_bytes = ul_dcch_msg.msg.c1()
                                   .ul_info_transfer()
                                   .crit_exts.c1()
                                   .ul_info_transfer_r8()
                                   .ded_info_type.ded_info_nas()
                                   .size();
            memcpy(nas_msg->msg,
                   ul_dcch_msg.msg.c1()
                       .ul_info_transfer()
                       .crit_exts.c1()
                       .ul_info_transfer_r8()
                       .ded_info_type.ded_info_nas()
                       .data(),
                   nas_msg->N_bytes);
            ret = decode_nas_ul(decoding_mem, nas_msg->msg, nas_msg->N_bytes);
        }
    }
    return ret;
}

/*Identity response with IMSI/IMEI or IMSI attach*/
int PUSCH_Decoder::decode_nas_ul(DCI_UL &decoding_mem, uint8_t *sdu_ptr, int length)
{
    int ret = SRSRAN_ERROR;
    s1ap_pdu_c rx_pdu; // asn1::s1ap::s1ap_pdu_c //using s1ap_pdu_t = asn1::s1ap::s1ap_pdu_c;
    cbit_ref bref(sdu_ptr, length);
    int asn1_result = rx_pdu.unpack(bref);
    srsran::unique_byte_buffer_t nas_msg = srsran::make_byte_buffer();
    memcpy(nas_msg->msg, sdu_ptr, length);
    nas_msg->N_bytes = length;
    uint8_t pd, msg_type, sec_hdr_type;
    LIBLTE_ERROR_ENUM err;
    liblte_mme_parse_msg_sec_header((LIBLTE_BYTE_MSG_STRUCT *)nas_msg.get(), &pd, &sec_hdr_type);
    if (sec_hdr_type != LIBLTE_MME_SECURITY_HDR_TYPE_INTEGRITY_AND_CIPHERED &&
        sec_hdr_type != LIBLTE_MME_SECURITY_HDR_TYPE_INTEGRITY_AND_CIPHERED_WITH_NEW_EPS_SECURITY_CONTEXT)
    {
        liblte_mme_parse_msg_header((LIBLTE_BYTE_MSG_STRUCT *)nas_msg.get(), &pd, &msg_type);

        if (msg_type == LIBLTE_MME_MSG_TYPE_IDENTITY_RESPONSE)
        {
            LIBLTE_MME_ID_RESPONSE_MSG_STRUCT identity_response;
            LIBLTE_BYTE_MSG_STRUCT msg;
            memcpy(&msg.msg, nas_msg->msg, nas_msg->N_bytes);
            msg.N_bytes = nas_msg->N_bytes;
            err = liblte_mme_unpack_identity_response_msg(&msg, &identity_response);
            if (err == LIBLTE_SUCCESS && identity_response.mobile_id.type_of_id == LIBLTE_MME_MOBILE_ID_TYPE_IMSI)
            {
                std::string imsi_str = "";
                for (int z = 0; z < 15; z++)
                {
                    imsi_str.append(std::to_string(identity_response.mobile_id.imsi[z]));
                }
                print_api(ul_sf.tti, decoding_mem.rnti, ID_IMSI, imsi_str, MSG_ID_RES);
                mcstracking->increase_nof_api_msg();
                ret = SRSRAN_SUCCESS;
            }
            else if (err == LIBLTE_SUCCESS && identity_response.mobile_id.type_of_id == LIBLTE_MME_MOBILE_ID_TYPE_IMEI)
            {
                std::string imei_str = "";
                for (int z = 0; z < 15; z++)
                {
                    imei_str.append(std::to_string(identity_response.mobile_id.imei[z]));
                }
                print_api(ul_sf.tti, decoding_mem.rnti, ID_IMEI, imei_str, MSG_ID_RES);
                mcstracking->increase_nof_api_msg();
                ret = SRSRAN_SUCCESS;
            }
            else if (err == LIBLTE_SUCCESS && identity_response.mobile_id.type_of_id == LIBLTE_MME_MOBILE_ID_TYPE_IMEISV)
            {
                std::string imei_str = "";
                for (int z = 0; z < 16; z++)
                {
                    imei_str.append(std::to_string(identity_response.mobile_id.imeisv[z]));
                }
                print_api(ul_sf.tti, decoding_mem.rnti, ID_IMEISV, imei_str, MSG_ID_RES);
                mcstracking->increase_nof_api_msg();
                ret = SRSRAN_SUCCESS;
            }
        }
        else if (err == LIBLTE_SUCCESS && msg_type == LIBLTE_MME_MSG_TYPE_ATTACH_REQUEST)
        {
            LIBLTE_MME_ATTACH_REQUEST_MSG_STRUCT attach_req;
            LIBLTE_BYTE_MSG_STRUCT msg;
            memcpy(&msg.msg, nas_msg->msg, nas_msg->N_bytes);
            msg.N_bytes = nas_msg->N_bytes;
            /*Unpack Attach request*/
            err = liblte_mme_unpack_attach_request_msg(&msg, &attach_req);
            if (attach_req.eps_mobile_id.type_of_id == LIBLTE_MME_EPS_MOBILE_ID_TYPE_IMSI)
            {
                std::string imsi_str = "";
                for (int z = 0; z < 15; z++)
                {
                    imsi_str.append(std::to_string(attach_req.eps_mobile_id.imsi[z]));
                }
                print_api(ul_sf.tti, decoding_mem.rnti, ID_IMSI, imsi_str, MSG_ATT_REQ);
                mcstracking->increase_nof_api_msg();
                ret = SRSRAN_SUCCESS;
            }
            else if (attach_req.eps_mobile_id.type_of_id == LIBLTE_MME_EPS_MOBILE_ID_TYPE_GUTI)
            {
                std::stringstream ss;
                ss << std::hex << attach_req.eps_mobile_id.guti.m_tmsi;
                std::string m_tmsi_str = ss.str();
                print_api(ul_sf.tti, decoding_mem.rnti, ID_TMSI, m_tmsi_str, MSG_ATT_REQ);
                mcstracking->increase_nof_api_msg();
                ret = SRSRAN_SUCCESS;
            }
            else if (attach_req.eps_mobile_id.type_of_id == LIBLTE_MME_EPS_MOBILE_ID_TYPE_IMEI)
            {
                std::string imei_str = "";
                for (int z = 0; z < 15; z++)
                {
                    imei_str.append(std::to_string(attach_req.eps_mobile_id.imei[z]));
                }
                print_api(ul_sf.tti, decoding_mem.rnti, ID_IMEI, imei_str, MSG_ATT_REQ);
                mcstracking->increase_nof_api_msg();
                ret = SRSRAN_SUCCESS;
            }
        }
    }
    return ret;
}

/* Run decode function after setup config, grant*/
void PUSCH_Decoder::decode_run(std::string info, DCI_UL &decoding_mem, std::string modulation_mode, float falcon_signal_power)
{
    int mcs_idx = ul_cfg.pusch.grant.tb.mcs_idx;
    srsran_softbuffer_rx_reset_tbs(ul_cfg.pusch.softbuffers.rx, ul_cfg.pusch.grant.tb.tbs);

    /*Do channel estimation to calculate timing difference between UL & DL subframes, because of diffrent propagation times*/
    int ret = srsran_chest_ul_estimate_pusch(&enb_ul.chest, &ul_sf, &ul_cfg.pusch, enb_ul.sf_symbols, &enb_ul.chest_res);

    /*Use channel estimation result to perform channel equalizer to compensate the time delay*/
    pusch_res.crc = false; // reset crc result
    if (ret == SRSRAN_SUCCESS)
    {
        ret = srsran_pusch_decode(&enb_ul.pusch, &ul_sf, &ul_cfg.pusch, &enb_ul.chest_res, enb_ul.sf_symbols, &pusch_res);
    }

    /*Only print debug when SNR of RNTI >= 1 */
    if ((en_debug) && (enb_ul.chest_res.snr_db >= 2) ) // && (enb_ul.chest_res.snr_db >= 1)
    { //|| target_rnti !=0
        float signal_power = enb_ul.chest_res.snr_db;
        float falcon_signal_power = 0.0f;
        float tmp_sum = 0.0f;
        for (uint32_t rb_idx = 0; rb_idx < ul_cfg.pusch.grant.L_prb; rb_idx++)
        {
            tmp_sum += sf_power->getRBPowerUL().at(ul_cfg.pusch.grant.n_prb[0] + rb_idx);
        }
        falcon_signal_power = tmp_sum / ul_cfg.pusch.grant.L_prb;
        print_debug(decoding_mem, info, modulation_mode, signal_power, enb_ul.chest_res.noise_estimate_dbm, falcon_signal_power);
    }

    if (pusch_res.crc == true && ul_cfg.pusch.grant.tb.tbs != 0)
    {
        int length = ul_cfg.pusch.grant.tb.tbs / 8;
        pcapwriter->write_ul_crnti(pusch_res.data, length, ul_cfg.pusch.rnti, ul_sf.tti);

        /*Update max UL modulation scheme 16/64/256QAM when mcs index > 20*/
        if (mcs_idx > 20 && decoding_mem.mcs_mod == UL_SNIFFER_UNKNOWN_MOD)
        {
            if (info == "[PUSCH-16 ]")
            {
                mcstracking->update_RNTI_ul(decoding_mem.rnti, UL_SNIFFER_16QAM_MAX);
            }
            else if (info == "[PUSCH-64 ]")
            {
                mcstracking->update_RNTI_ul(decoding_mem.rnti, UL_SNIFFER_64QAM_MAX);
            }
            else if (info == "[PUSCH-256]")
            {
                mcstracking->update_RNTI_ul(decoding_mem.rnti, UL_SNIFFER_256QAM_MAX);
            }
            /*When mcs index < 20, only 2 possible max modulation scheme 16/256QAM */
        }
        else if (mcs_idx > 0 && decoding_mem.mcs_mod == UL_SNIFFER_UNKNOWN_MOD && info == "[PUSCH-256]")
        {
            mcstracking->update_RNTI_ul(decoding_mem.rnti, UL_SNIFFER_256QAM_MAX);
        }
        decoding_mem.decoded = 1;

        /* [API] Decode RRC Connection Setup and UECapabilityInformation*/
        int api_ret = SRSRAN_ERROR;
        if (decoding_mem.is_rar_gant && (api_mode == 0 || api_mode == 3))
        {
            srsran::sch_pdu pdu(10, srslog::fetch_basic_logger("MAC"));
            pdu.init_rx(length, true);
            pdu.parse_packet(pusch_res.data);
            while (pdu.next())
            {
                if (pdu.get()->is_sdu())
                {
                    int payload_length = pdu.get()->get_payload_size();
                    uint8_t *sdu_ptr = pdu.get()->get_sdu_ptr();
                    /* Decode RRC Connection Request when found valid sdu from MAC pdu*/
                    ret = decode_rrc_connection_request(decoding_mem, sdu_ptr, payload_length);
                }
            }
            if (ret == SRSRAN_SUCCESS)
            {
                pcapwriter->write_ul_crnti_api(pusch_res.data, length, ul_cfg.pusch.rnti, ul_sf.tti);
                api_ret = SRSRAN_ERROR;
            }
        }
        else if (api_mode > 0)
        { // Decode DCCH (api mode 1,2,3)
            srsran::sch_pdu pdu(10, srslog::fetch_basic_logger("MAC"));
            pdu.init_rx(length, true);
            pdu.parse_packet(pusch_res.data);
            while (pdu.next())
            {
                /*LCID 1 & 2*/
                if (pdu.get()->is_sdu() && (pdu.get()->get_sdu_lcid() == 1 || pdu.get()->get_sdu_lcid() == 2))
                {
                    int payload_length = pdu.get()->get_payload_size();
                    uint8_t *sdu_ptr = pdu.get()->get_sdu_ptr();
                    /*Only RLC data pdu*/
                    if (!rlc_am_is_control_pdu(sdu_ptr))
                    {
                        rlc_amd_pdu_header_t header = {};
                        uint32_t payload_len = payload_length;
                        rlc_am_read_data_pdu_header(&sdu_ptr, &payload_len, &header);
                        /*Only decode full frame, not fragment of frame (fi == 0 means full RRC frame)*/
                        if (!header.rf && header.fi == 0)
                        {
                            srsran::unique_byte_buffer_t pdcp_pdu = srsran::make_byte_buffer();
                            pdcp_pdu->N_bytes = payload_len;
                            memcpy(pdcp_pdu->msg, sdu_ptr, pdcp_pdu->N_bytes);
                            /*Discard pdcp header , assume that pdcp header size = 1 byte*/
                            pdcp_pdu->msg += 1;
                            pdcp_pdu->N_bytes -= 1;
                            uint8_t pd, msg_type, sec_hdr_type;
                            liblte_mme_parse_msg_sec_header((LIBLTE_BYTE_MSG_STRUCT *)pdcp_pdu.get(), &pd, &sec_hdr_type);
                            /*Only decode NAS without encryption*/
                            if ((sec_hdr_type == LIBLTE_MME_SECURITY_HDR_TYPE_PLAIN_NAS) ||
                                (sec_hdr_type == LIBLTE_MME_SECURITY_HDR_TYPE_INTEGRITY) ||
                                (sec_hdr_type == LIBLTE_MME_SECURITY_HDR_TYPE_INTEGRITY_WITH_NEW_EPS_SECURITY_CONTEXT))
                            {
                                // /*Discard pdcp header , assume that pdcp header size = 1 byte*/
                                // pdcp_pdu->msg       += 1;
                                // pdcp_pdu->N_bytes   -= 1;

                                /* Decode UL DCCH messages*/
                                api_ret = decode_ul_dcch(decoding_mem, pdcp_pdu->msg, pdcp_pdu->N_bytes);
                            }
                        }
                    }
                }
            }
            if (api_ret == SRSRAN_SUCCESS)
            {
                pcapwriter->write_ul_crnti_api(pusch_res.data, length, ul_cfg.pusch.rnti, ul_sf.tti);
                api_ret = SRSRAN_ERROR;
            }
        }
    }
}

void print_ul_grant_dci_0(srsran_pusch_grant_t &ul_grant, uint16_t tti, uint16_t rnti)
{
    std::cout << "[DCI] SF: " << tti / 10 << ":" << tti % 10 << "-RNTI: " << rnti << " -L_prb: " << ul_grant.L_prb << " -MOD: " << ul_grant.tb.mod << " -tbs: " << ul_grant.tb.tbs << " -RV: " << ul_grant.tb.rv << std::endl;
}

void PUSCH_Decoder::decode()
{
    if (decoder_a){
        enb_ul.in_buffer = original_buffer[0]; // 0 for downlink, 1 for uplink, now 0 because there are 2 separate buffers
    }else if (decoder_b){
        enb_ul.in_buffer = original_buffer[1]; // 0 for downlink, 1 for uplink, now 0 because there are 2 separate buffers
    }
    srsran_enb_ul_fft(&enb_ul);            // run FFT to uplink samples
    sf_power->computePower(enb_ul.sf_symbols);

    /*combine Uplink grant detected from RAR response (msg 2) and Uplink grant detected from DCI0*/
    if (dci_ul != nullptr || rar_dci_ul != nullptr)
    {
        if (rar_dci_ul != nullptr && dci_ul != nullptr)
        {
            int rar_size = rar_dci_ul->size();
            if (rar_size > 0)
            {
                for (int rar_idx = 0; rar_idx < rar_size; rar_idx++)
                {
                    dci_ul->push_back(rar_dci_ul->at(rar_idx));
                }
            }
        }
        else if (rar_dci_ul != nullptr && dci_ul == nullptr)
        {
            dci_ul = rar_dci_ul;
        }
        /*Try to decode all member in grant list*/
        for (auto decoding_mem : (*dci_ul))
        {
            /*Investigate current decoding member to know it has a valid UL grant or not*/
            valid_ul_grant = investigate_valid_ul_grant(decoding_mem);
            /*Only decode member with valid UL grant*/
            if ((decoding_mem.rnti == target_rnti) || (valid_ul_grant == SRSRAN_SUCCESS))
            {
                /*Setup uplink config for decoding*/
                ul_cfg.pusch.rnti = decoding_mem.rnti;
                ul_cfg.pusch.enable_64qam = false; // check here for 64/16QAM
                ul_cfg.pusch.meas_ta_en = true;    // enable ta measurement
                ul_cfg.pusch.grant = *decoding_mem.ran_ul_grant.get();
                int mcs_idx = ul_cfg.pusch.grant.tb.mcs_idx;
                pusch_res.crc = false;
                /*Get Number of ack which was calculated in Subframe worker last 4 ms*/
                ul_cfg.pusch.uci_cfg.ack[0].nof_acks = decoding_mem.nof_ack;
                // ul_cfg.pusch.uci_cfg.cqi.rank_is_not_one            = (decoding_mem.nof_ack == 2)?true:false;

                /*get UE-specific configuration from database*/
                ltesniffer_ue_spec_config_t ue_config = mcstracking->get_ue_config_rnti(decoding_mem.rnti);
                ul_cfg.pusch.uci_cfg.cqi.type = ue_config.cqi_config.type;
                ul_cfg.pusch.uci_offset = ue_config.uci_config;
                /*If eNB requests for Aperiodic CSI report*/
                if (decoding_mem.ran_ul_dci->cqi_request == true)
                {
                    ul_cfg.pusch.uci_cfg.cqi.four_antenna_ports = false;
                    ul_cfg.pusch.uci_cfg.cqi.data_enable = true;
                    ul_cfg.pusch.uci_cfg.cqi.pmi_present = false;
                    ul_cfg.pusch.uci_cfg.cqi.rank_is_not_one = false;
                    ul_cfg.pusch.uci_cfg.cqi.N = ul_sniffer_cqi_hl_get_no_subbands(enb_ul.cell.nof_prb);
                    ul_cfg.pusch.uci_cfg.cqi.ri_len = 1; // only for TM3 and TM4 // srsran_ri_nof_bits(&enb_ul.cell)
                }
                else
                {
                    ul_cfg.pusch.uci_cfg.cqi.data_enable = false;
                    ul_cfg.pusch.uci_cfg.cqi.ri_len = 0;
                }
                /*Find correct mcs table from database*/
                ul_sniffer_mod_tracking_t mcs_mod = mcstracking->find_tracking_info_RNTI_ul(decoding_mem.rnti);
                std::string modulation_mode = "Unknown";
                int ret = SRSRAN_ERROR;
                /*If mcs_idx > 20 then check mcstracking to decode properly*/
                if (mcs_idx > 20 && mcs_idx < 29)
                {
                    switch (mcs_mod)
                    {
                    case UL_SNIFFER_16QAM_MAX:
                        decoding_mem.mcs_mod = UL_SNIFFER_16QAM_MAX;
                        ul_cfg.pusch.enable_64qam = false;
                        modulation_mode = modulation_mode_string(mcs_idx, false);
                        decode_run("[PUSCH-16 ]", decoding_mem, modulation_mode, 0);
                        break;
                    case UL_SNIFFER_64QAM_MAX:
                        decoding_mem.mcs_mod = UL_SNIFFER_64QAM_MAX;
                        ul_cfg.pusch.enable_64qam = true;
                        modulation_mode = modulation_mode_string(mcs_idx, true);
                        decode_run("[PUSCH-64 ]", decoding_mem, modulation_mode, 0);
                        break;
                    case UL_SNIFFER_256QAM_MAX:
                        decoding_mem.mcs_mod = UL_SNIFFER_256QAM_MAX;
                        ul_cfg.pusch.enable_64qam = true;
                        modulation_mode = modulation_mode_string_256(mcs_idx);
                        ul_cfg.pusch.grant = *decoding_mem.ran_ul_grant_256.get();
                        if (ul_cfg.pusch.grant.L_prb < 110 && ul_cfg.pusch.grant.L_prb > 0)
                        {
                            decode_run("[PUSCH-256]", decoding_mem, modulation_mode, 0);
                        }
                        break;
                    case UL_SNIFFER_UNKNOWN_MOD:
                        // string for debug:
                        modulation_mode = modulation_mode_string(mcs_idx, true);
                        /* reset buffer and CRC checking */
                        pusch_res.crc = false;
                        // ret = srsran_chest_ul_estimate_pusch(&enb_ul.chest, &ul_sf, &ul_cfg.pusch, enb_ul.sf_symbols, &enb_ul.chest_res);
                        if (mcs_idx <= 28)
                        {
                            /*Compute avg signal power for PRB in UL grant*/
                            float falcon_signal_power = 0.0f;
                            float tmp_sum = 0.0f;
                            for (uint32_t rb_idx = 0; rb_idx < ul_cfg.pusch.grant.L_prb; rb_idx++)
                            {
                                tmp_sum += sf_power->getRBPowerUL().at(ul_cfg.pusch.grant.n_prb[0] + rb_idx);
                            }
                            falcon_signal_power = tmp_sum / ul_cfg.pusch.grant.L_prb;
                            decode_run("[PUSCH-16 ]", decoding_mem, modulation_mode, falcon_signal_power);

                            if (pusch_res.crc == false && mcs_idx > 20)
                            {
                                /* Try 64QAM table if 16QAM failed*/
                                ul_cfg.pusch.rnti = decoding_mem.rnti;
                                ul_cfg.pusch.enable_64qam = true; // 64QAM
                                ul_cfg.pusch.meas_ta_en = true;   // enable ta measurement
                                ul_cfg.pusch.grant = *decoding_mem.ran_ul_grant.get();

                                decode_run("[PUSCH-64 ]", decoding_mem, modulation_mode, falcon_signal_power);

                                if (pusch_res.crc == false)
                                { // try 256QAM table if 2 cases above failed
                                    ul_cfg.pusch.rnti = decoding_mem.rnti;
                                    ul_cfg.pusch.enable_64qam = true;
                                    ul_cfg.pusch.meas_ta_en = true; // enable ta measurement
                                    ul_cfg.pusch.grant = *decoding_mem.ran_ul_grant_256.get();
                                    modulation_mode = modulation_mode_string_256(mcs_idx);
                                    if (ul_cfg.pusch.grant.L_prb < 110 && ul_cfg.pusch.grant.L_prb > 0)
                                    {
                                        decode_run("[PUSCH-256]", decoding_mem, modulation_mode, 0);
                                    }
                                }
                            }
                        }
                        else
                        {
                            // Do nothing if mimo ret error
                        }
                        break;
                    default:
                        break;
                    }
                }
                else if (mcs_idx <= 20)
                { // if mcs_idx <= 20 then try only 16QAM or 256QAM (64QAM is enabled when mcs idx > 20)
                    switch (mcs_mod)
                    {
                    case UL_SNIFFER_16QAM_MAX:
                    case UL_SNIFFER_64QAM_MAX:
                        ul_cfg.pusch.enable_64qam = false;
                        modulation_mode = modulation_mode_string(mcs_idx, false);
                        decode_run("[PUSCH-16 ]", decoding_mem, modulation_mode, 0);
                        break;
                    case UL_SNIFFER_256QAM_MAX:
                        ul_cfg.pusch.enable_64qam = true;
                        ul_cfg.pusch.grant = *decoding_mem.ran_ul_grant_256.get();
                        modulation_mode = modulation_mode_string_256(mcs_idx);
                        if (ul_cfg.pusch.grant.L_prb < 110 && ul_cfg.pusch.grant.L_prb > 0)
                        {
                            decode_run("[PUSCH-256]", decoding_mem, modulation_mode, 0);
                        }
                        break;
                    case UL_SNIFFER_UNKNOWN_MOD:
                        ul_cfg.pusch.enable_64qam = false;
                        modulation_mode = modulation_mode_string(mcs_idx, false);
                        decode_run("[PUSCH-16 ]", decoding_mem, modulation_mode, 0);
                        if (pusch_res.crc == false)
                        { // try 256QAM table if case above failed
                            ul_cfg.pusch.grant = *decoding_mem.ran_ul_grant_256.get();
                            modulation_mode = modulation_mode_string_256(mcs_idx);
                            if (ul_cfg.pusch.grant.L_prb < 110 && ul_cfg.pusch.grant.L_prb > 0)
                            {
                                ul_cfg.pusch.enable_64qam = true;
                                decode_run("[PUSCH-256]", decoding_mem, modulation_mode, 0);
                            }
                        }
                    default:
                        // do nothing
                        break;
                    }
                }
                /*Update statistic when SNR is higher than 1, the statistic showed on terminal is only for RNTIs with SNR >=1*/
                if (enb_ul.chest_res.snr_db >= 1)
                { // enb_ul.chest_res.snr_db >= 1
                    mcstracking->update_statistic_ul(decoding_mem.rnti, pusch_res.crc, decoding_mem, enb_ul.chest_res.snr_db, enb_ul.chest_res.ta_us);
                }
            }
            else
            {
                // Do nothing
            }
        }
    }
}

void PUSCH_Decoder::init_pusch_decoder(std::vector<DCI_UL> *dci_ul_,
                                       std::vector<DCI_UL> *rar_dci_ul_,
                                       srsran_ul_sf_cfg_t &ul_sf_,
                                       SubframePower *sf_power_)
{
    dci_ul = dci_ul_;
    rar_dci_ul = rar_dci_ul_;
    ul_sf = ul_sf_;
    sf_power = sf_power_;
}

int PUSCH_Decoder::check_valid_prb_ul(uint32_t nof_prb)
{
    if (nof_prb <= 100)
    {
        return valid_prb_ul[nof_prb];
    }
    return false;
}

std::string PUSCH_Decoder::modulation_mode_string(int idx, bool max_64qam)
{
    std::string ret = "";
    if (idx <= 10)
    {
        ret = "QPSK";
    }
    else if (idx <= 20)
    {
        ret = "16QAM";
    }
    else if (idx <= 28 && max_64qam)
    {
        ret = "64QAM";
    }
    else if (idx <= 28 && !max_64qam)
    {
        ret = "16QAM";
    }
    else
    {
        ret = "ReTx";
    }
    return ret;
}

std::string PUSCH_Decoder::modulation_mode_string_256(int idx)
{
    std::string ret = "";
    if (idx <= 5)
    {
        ret = "QPSK";
    }
    else if (idx <= 13)
    {
        ret = "16QAM";
    }
    else if (idx <= 22)
    {
        ret = "64QAM";
    }
    else if (idx <= 28)
    {
        ret = "256QAM";
    }
    else
    {
        ret = "ReTx";
    }
    return ret;
}

void PUSCH_Decoder::set_rach_config(srsran_prach_cfg_t prach_cfg_)
{
    prach_cfg = prach_cfg_;
    if (srsran_prach_init(&prach, srsran_symbol_sz(enb_ul.cell.nof_prb)))
    {
        std::cout << "Init PRACH failed" << std::endl;
    }
    if (srsran_prach_set_cfg(&prach, &prach_cfg, enb_ul.cell.nof_prb))
    {
        std::cout << "Config PRACH failed" << std::endl;
    }
    srsran_prach_set_detect_factor(&prach, 60);
    nof_sf = (uint32_t)ceilf(prach.T_tot * 1000);
}

void PUSCH_Decoder::work_prach()
{
    uint32_t prach_nof_det = 0;
    if (srsran_prach_tti_opportunity(&prach, ul_sf.tti, -1))
    {
        memcpy(&samples[0],
               original_buffer[0],
               sizeof(cf_t) * SRSRAN_SF_LEN_PRB(enb_ul.cell.nof_prb));
        // Detect possible PRACHs
        srsran_prach_detect_offset(&prach,
                                   prach_cfg.freq_offset,
                                   &samples[prach.N_cp],
                                   SRSRAN_SF_LEN_PRB(enb_ul.cell.nof_prb) - prach.N_cp,
                                   prach_indices,
                                   prach_offsets,
                                   prach_p2avg,
                                   &prach_nof_det);

        if (prach_nof_det)
        {
            int max_idx = 0;
            float peak = 0;
            for (uint32_t i = 0; i < prach_nof_det; i++)
            {
                if (prach_p2avg[i] > peak)
                {
                    peak = prach_p2avg[i];
                    max_idx = i;
                }
            }
            if (en_debug)
            {
                printf("PRACH: %d/%d, preamble=%d, offset=%.1f us, peak2avg=%.1f \n",
                       max_idx + 1,
                       prach_nof_det,
                       prach_indices[max_idx],
                       prach_offsets[max_idx] * 1e6,
                       prach_p2avg[max_idx]);
            }
        }
    }
}

void PUSCH_Decoder::print_debug(DCI_UL &decoding_mem, std::string offset_name, std::string modulation_mode, float signal_pw, double noise, double falcon_sgl_pwr)
{
    std::cout << "[" << debug_str << "]";
    std::cout << std::left << std::setw(12) << offset_name << " SF: ";
    std::cout << std::left << std::setw(4) << (int)ul_sf.tti / 10 << "." << (int)ul_sf.tti % 10;
    std::cout << " -- RNTI: ";
    std::cout << std::left << std::setw(6) << decoding_mem.rnti;

    std::cout << GREEN << " -- DL-UL(us): ";
    if (enb_ul.chest_res.ta_us > 0)
    {
        std::cout << "+";
    }
    else if (enb_ul.chest_res.ta_us < 0)
    {
        std::cout << "-";
    }
    else
    {
        std::cout << " ";
    }
    std::cout << std::left << std::setw(5) << abs(enb_ul.chest_res.ta_us) << RESET;
    std::cout << " -- SNR(db): ";
    std::cout << std::left << std::setw(6) << std::setprecision(3) << enb_ul.chest_res.snr_db;

    // std::cout << " -- F_Pwr: ";
    // std::string pwr_sign;
    // int width = 0;
    // if (falcon_sgl_pwr < 0) {
    //     pwr_sign = "";
    //     width = 7;

    // } else {
    //     pwr_sign = " ";
    //     width = 6;
    // }
    // std::cout << std::left << pwr_sign << std::setw(width) << std::setprecision(3) << falcon_sgl_pwr;

    std::cout << " -- CQI RQ: ";
    std::cout << decoding_mem.ran_ul_dci->cqi_request << "|" << decoding_mem.ran_ul_dci->multiple_csi_request_present;

    std::cout << " -- Noise Pwr: ";
    std::cout << std::left << std::setw(6) << std::setprecision(3) << noise;

    std::cout << YELLOW << " -- MCS: ";
    std::cout << std::left << std::setw(3) << ul_cfg.pusch.grant.tb.mcs_idx << RESET;

    std::cout << YELLOW << " -- ";
    std::cout << std::left << std::setw(6) << modulation_mode << RESET;

    std::cout << " -- ";
    if (pusch_res.crc == false)
    {
        std::cout << RED << std::setw(7) << "FAILED" << RESET;
        std::cout << " -- Len: " << ul_cfg.pusch.grant.tb.tbs / 8;
    }
    else
    {
        std::cout << BOLDGREEN << std::setw(7) << "SUCCESS" << RESET;
        std::cout << " -- Len: " << ul_cfg.pusch.grant.tb.tbs / 8;
    }
    if (decoding_mem.is_rar_gant)
    {
        std::cout << " -- RAR";
    }
    if (decoding_mem.is_retx == 1)
    {
        std::cout << " -- ReTX-UL";
    }
    std::cout << std::endl;
}

void PUSCH_Decoder::print_success(DCI_UL &decoding_mem, std::string offset_name, int table)
{
    std::cout << offset_name << "------->>>>>>"
              << " SF: " << (int)ul_sf.tti / 10 << "-" << (int)ul_sf.tti % 10;
    std::cout << " Success RNTI: " << decoding_mem.rnti;
    std::cout << " -- length: " << ul_cfg.pusch.grant.tb.tbs / 8;
    std::cout << " -- table: " << (table == 1) ? "64QAM" : "16QAM";
    std::cout << " -- TA(us): " << enb_ul.chest_res.ta_us;
    std::cout << " -- SNR: " << enb_ul.chest_res.snr_db << std::endl;
}

void PUSCH_Decoder::print_ul_grant(srsran_pusch_grant_t &grant)
{
    std::cout << "Decoding PUSCH grant: " << std::endl;
    std::cout << "L_prb: " << grant.L_prb << std::endl;
    std::cout << "n_prb: " << grant.n_prb[0] << ":" << grant.n_prb[1] << std::endl;
    std::cout << "n_prb_tilde: " << grant.n_prb_tilde[0] << ":" << grant.n_prb_tilde[1] << std::endl;
    std::cout << "freq_hopping: " << grant.freq_hopping << std::endl;
    std::cout << "nof_re: " << grant.nof_re << std::endl;
    std::cout << "nof_symb: " << grant.nof_symb << std::endl;
    std::cout << "n_dmrs: " << grant.n_dmrs << std::endl;
    std::cout << "tb: "
              << "mod: " << grant.tb.mod << " -- tbs: " << grant.tb.tbs << " -- rv: " << grant.tb.rv << "--mcs: " << grant.tb.mcs_idx << std::endl;
    std::cout << "last_tb: "
              << "mod: " << grant.last_tb.mod << " -- tbs: " << grant.last_tb.tbs << " -- rv: " << grant.last_tb.rv << "--mcs: " << grant.last_tb.mcs_idx;
    std::cout << "---------------------------------------" << std::endl;
}

void PUSCH_Decoder::print_uci(srsran_uci_value_t *uci)
{
    if (uci->cqi.data_crc == true)
    {
        std::cout << "[UCI] ";
        std::cout << " SR: " << uci->scheduling_request;
        std::cout << " -- RI: " << uci->ri << std::endl;
        std::cout << " -- CQI wideband: " << uci->cqi.wideband.wideband_cqi << "|" << uci->cqi.wideband.pmi << "|" << uci->cqi.wideband.spatial_diff_cqi << std::endl;
        std::cout << " -- CQI ue: " << uci->cqi.subband_ue.subband_label << "|" << uci->cqi.subband_ue.subband_cqi << std::endl;
        std::cout << " -- CQI hl sub cw0: " << uci->cqi.subband_hl.wideband_cqi_cw0 << " -- CQI hl sub cw1: " << uci->cqi.subband_hl.wideband_cqi_cw1 << std::endl;
    }
}

std::string convert_id_name(int id)
{
    std::string ret = "-";
    switch (id)
    {
    case ID_RAN_VAL:
        ret = "RandomValue";
        break;
    case ID_TMSI:
        ret = "TMSI";
        break;
    case ID_CON_RES:
        ret = "Contention Resolution";
        break;
    case ID_IMSI:
        ret = "IMSI";
        break;
    case ID_IMEI:
        ret = "IMEI";
        break;
    case ID_IMEISV:
        ret = "IMEISV";
        break;
    default:
        ret = "-";
        break;
    }
    return ret;
}
std::string convert_msg_name(int msg)
{
    std::string ret = "-";
    switch (msg)
    {
    case 0:
        ret = "RRC Connection Request";
        break;
    case 1:
        ret = "RRC Connection Setup";
        break;
    case 2:
        ret = "Attach Request";
        break;
    case 3:
        ret = "Identity Response";
        break;
    case 4:
        ret = "UECapability";
        break;
    default:
        ret = "-";
        break;
    }
    return ret;
}
void PUSCH_Decoder::print_api(uint32_t tti, uint16_t rnti, int id, std::string value, int msg)
{
    std::cout << std::left << std::setw(4) << tti / 10 << "-" << std::left << std::setw(5) << tti % 10;
    std::string id_name = convert_id_name(id);
    std::cout << std::left << std::setw(26) << id_name;
    std::cout << std::left << std::setw(17) << value;
    std::cout << std::left << std::setw(11) << rnti;
    std::string msg_name = convert_msg_name(msg);
    std::cout << std::left << std::setw(25) << msg_name;
    std::cout << std::endl;
}

int PUSCH_Decoder::investigate_valid_ul_grant(DCI_UL &decoding_mem)
{
    int ret = SRSRAN_SUCCESS;
    if (decoding_mem.is_rar_gant)
    {
        return SRSRAN_SUCCESS;
    }
    /*if RNTI == 0*/
    if (decoding_mem.rnti == 0)
    {
        ret = SRSRAN_ERROR;
    }
    /*if Transport Block size = 0 (wrong DCI detection or retransmission or pdsch for ack and uci)*/
    if (decoding_mem.ran_ul_grant->tb.tbs == 0 || decoding_mem.ran_ul_grant_256->tb.tbs == 0)
    {
        ret = SRSRAN_ERROR;
    }
    /*if number of PRB is invalid*/
    if (!check_valid_prb_ul(decoding_mem.ran_ul_grant->L_prb))
    {
        ret = SRSRAN_ERROR;
    }

    return ret;
}
