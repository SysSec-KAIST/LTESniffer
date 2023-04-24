#include "include/DL_Sniffer_PDSCH.h"

float p_a_array[8]{-6, -4.77, -3, -1.77, 0, 1, 2, 3};

PDSCH_Decoder::PDSCH_Decoder(uint32_t idx, 
							 LTESniffer_pcap_writer *pcapwriter, 
							 MCSTracking *mcs_tracking,
							 RNTIManager& rntiManager,
							 HARQ *harq,
							 int mcs_tracking_mode, 
							 int harq_mode, 
							 int nof_antenna):
idx(idx),
sf_idx(0),
sfn(0),
buffer(),
falcon_ue_dl(),
dl_sf(),
ue_dl_cfg(),
ran_dl_collection(),
pdsch_res(),
pdsch_cfg(),
pcapwriter(pcapwriter),
mcs_tracking(mcs_tracking),
rntiManager(rntiManager),
harq(harq),
mcs_tracking_mode(mcs_tracking_mode),
sib2(),
nof_antenna(nof_antenna),
harq_mode(harq_mode)
{
	set_debug_mode (mcs_tracking->get_debug_mode());
	set_api_mode   (mcs_tracking->get_api_mode());
	set_target_rnti(mcs_tracking->get_target_rnti());
	/* Set algorithm for channel estimation*/
	pdsch_cfg = new srsran_pdsch_cfg_t;
	pdsch_res = new srsran_pdsch_res_t[SRSRAN_MAX_CODEWORDS];
	ZERO_OBJECT(*pdsch_cfg);
	for (uint32_t i = 0; i < SRSRAN_MAX_CODEWORDS; i++) {
		//pdsch_cfg->softbuffers.rx[i] = new srsran_softbuffer_rx_t;
		//srsran_softbuffer_rx_init(pdsch_cfg->softbuffers.rx[i], SRSRAN_MAX_PRB);
		buffer [i] = new srsran_softbuffer_rx_t;
		srsran_softbuffer_rx_init(buffer[i], SRSRAN_MAX_PRB);
	}
	for (int i = 0; i < SRSRAN_MAX_CODEWORDS; i++) {
		pdsch_res[i].payload = srsran_vec_u8_malloc(2000 * 8);
		if (!pdsch_res[i].payload) {
		ERROR("[PDSCH_Decoder] Allocating data\n");
		}
	}
}

PDSCH_Decoder::~PDSCH_Decoder()
{
	for (int i = 0; i < SRSRAN_MAX_CODEWORDS; i++) {
		srsran_vec_u8_zero(pdsch_res[i].payload, 2000 * 8);
		delete [] pdsch_res[i].payload;
		//srsran_softbuffer_rx_free(pdsch_cfg->softbuffers.rx[i]);
		srsran_softbuffer_rx_free(buffer[i]);
	}
	delete pdsch_cfg;
	pdsch_cfg = nullptr;
}

int PDSCH_Decoder::init_pdsch_decoder(falcon_ue_dl_t *_falcon_ue_dl,
									  srsran_dl_sf_cfg_t *_dl_sf,
									  srsran_ue_dl_cfg_t *_ue_dl_cfg,
									  std::vector<DL_Sniffer_DCI_DL> *_ran_dl_collection,
									  uint32_t _sfn,
									  uint32_t _sf_idx)
{
	falcon_ue_dl 		= _falcon_ue_dl;
	dl_sf 				= _dl_sf;
	ue_dl_cfg 			= _ue_dl_cfg;
	ran_dl_collection 	= _ran_dl_collection;
	sfn 				= _sfn;
	sf_idx 				= _sf_idx;
}

int PDSCH_Decoder::decode_imsi_paging(uint8_t* sdu_ptr, int length){
  pcch_msg_s     pcch_msg;
  asn1::cbit_ref bref(sdu_ptr, length);
  if (pcch_msg.unpack(bref) == asn1::SRSASN_SUCCESS or pcch_msg.msg.type().value == pcch_msg_type_c::types_opts::c1) {
	paging_s* paging = &pcch_msg.msg.c1().paging();
	if( paging->paging_record_list_present){
		paging_record_list_l paging_record_list = paging->paging_record_list;
		int record_size = paging_record_list.size();
		for (int record = 0; record < record_size; record++){
			paging_record_s paging_record = paging_record_list[record];
			if (paging_record.ue_id.type() == paging_ue_id_c::types_opts::imsi){
				//printf("Found IMSI paging\n");
			}
		}
	}
  }
}

int PDSCH_Decoder::decode_rrc_connection_setup(uint8_t* sdu_ptr, int length, ltesniffer_ue_spec_config_t *ue_config){
    dl_ccch_msg_s dl_ccch_msg;
    asn1::cbit_ref bref(sdu_ptr, length);
    int asn1_result = dl_ccch_msg.unpack(bref);
    if (asn1_result == asn1::SRSASN_SUCCESS && dl_ccch_msg.msg.type() == dl_ccch_msg_type_c::types_opts::c1){
        if (dl_ccch_msg.msg.c1().type().value == dl_ccch_msg_type_c::c1_c_::types::rrc_conn_setup){
            asn1::rrc::rrc_conn_setup_s con_setup = dl_ccch_msg.msg.c1().rrc_conn_setup();
            rrc_conn_setup_r8_ies_s* msg_r8 = &con_setup.crit_exts.c1().rrc_conn_setup_r8();
			rrc_con_set.rr_cfg_ded.phys_cfg_ded.pusch_cfg_ded.beta_offset_ack_idx = msg_r8->rr_cfg_ded.phys_cfg_ded.pusch_cfg_ded.beta_offset_ack_idx;
			rrc_con_set.rr_cfg_ded.phys_cfg_ded.pusch_cfg_ded.beta_offset_cqi_idx = msg_r8->rr_cfg_ded.phys_cfg_ded.pusch_cfg_ded.beta_offset_cqi_idx;
			rrc_con_set.rr_cfg_ded.phys_cfg_ded.pusch_cfg_ded.beta_offset_ri_idx = msg_r8->rr_cfg_ded.phys_cfg_ded.pusch_cfg_ded.beta_offset_ri_idx;

			/*get UE Specific config*/
			ue_config->p_a = p_a_array[msg_r8->rr_cfg_ded.phys_cfg_ded.pdsch_cfg_ded.p_a]; //convert p_a index to float number
			ue_config->uci_config.I_offset_ack = msg_r8->rr_cfg_ded.phys_cfg_ded.pusch_cfg_ded.beta_offset_ack_idx;
			ue_config->uci_config.I_offset_cqi = msg_r8->rr_cfg_ded.phys_cfg_ded.pusch_cfg_ded.beta_offset_cqi_idx;
			ue_config->uci_config.I_offset_ri  = msg_r8->rr_cfg_ded.phys_cfg_ded.pusch_cfg_ded.beta_offset_ri_idx;
			if (msg_r8->rr_cfg_ded.phys_cfg_ded.cqi_report_cfg.cqi_report_mode_aperiodic_present){
				asn1::rrc::cqi_report_mode_aperiodic_e aperiodic_mode = msg_r8->rr_cfg_ded.phys_cfg_ded.cqi_report_cfg.cqi_report_mode_aperiodic;
				if (aperiodic_mode == cqi_report_mode_aperiodic_opts::rm12){
					ue_config->cqi_config.type	= SRSRAN_CQI_TYPE_WIDEBAND;
				}else if (aperiodic_mode == cqi_report_mode_aperiodic_opts::rm20 || aperiodic_mode == cqi_report_mode_aperiodic_opts::rm22){
					ue_config->cqi_config.type	= SRSRAN_CQI_TYPE_SUBBAND_UE;
				} else if (aperiodic_mode == cqi_report_mode_aperiodic_opts::rm30 || aperiodic_mode == cqi_report_mode_aperiodic_opts::rm31){
					ue_config->cqi_config.type	= SRSRAN_CQI_TYPE_SUBBAND_HL;
				}
			}
			ue_config->has_ue_config = true;
			if (!has_default_config){
				default_ue_spec_config = *ue_config;
				default_ue_spec_config.has_ue_config = false;
				has_default_config = true;
			}
			return SRSRAN_SUCCESS;
		} else{
			return SRSRAN_ERROR;
		}
    }
	return SRSRAN_ERROR;
}


int PDSCH_Decoder::run_decode(int &mimo_ret, 
							   srsran_dci_format_t cur_format,
							   srsran_dci_dl_t *cur_ran_dci_dl,
							   srsran_pdsch_grant_t *cur_grant,
							   uint32_t cur_rnti,
							   std::string table,
							   std::string RNTI_name, 
							   uint32_t tti)
{
	int ret = 0;
	mimo_ret = dl_sniffer_config_mimo(&falcon_ue_dl->q->cell, cur_format, cur_ran_dci_dl, cur_grant);
	if (mimo_ret == SRSRAN_SUCCESS){
		/* config pdsch_cfg for decoding pdsch*/
		pdsch_cfg->grant = *cur_grant; //check again here
		pdsch_cfg->rnti = cur_rnti;
		
		for (int i = 0; i < SRSRAN_MAX_CODEWORDS; i++) {
			if (pdsch_cfg->grant.tb[i].enabled) {
				if (pdsch_cfg->grant.tb[i].rv < 0) {
					uint32_t k                = (sfn / 2) % 4;
					pdsch_cfg->grant.tb[i].rv = ((uint32_t)ceilf((float)1.5 * k)) % 4;
				}
				pdsch_cfg->softbuffers.rx[i] = buffer[i];
				srsran_softbuffer_rx_reset_tbs(pdsch_cfg->softbuffers.rx[i], (uint32_t)pdsch_cfg->grant.tb[i].tbs);
			}
		}

		//main function to decode
		if (pdsch_cfg->grant.tb[0].enabled||pdsch_cfg->grant.tb[1].enabled){
			if (srsran_ue_dl_decode_pdsch(falcon_ue_dl->q, dl_sf, pdsch_cfg, pdsch_res)) {
			ERROR("ERROR: Decoding PDSCH");
			}
		}
		//write pcap file
		for (uint32_t tb = 0; tb < SRSRAN_MAX_CODEWORDS; tb++) {
			if (pdsch_res[tb].crc){
				int result_length = pdsch_cfg->grant.tb[tb].tbs/8;
				write_pcap(RNTI_name, pdsch_res[tb].payload, result_length, cur_rnti, tti, false);
				
				if (RNTI_name == "P_RNTI" && (api_mode == 2 || api_mode == 3)){ //IMSI catching modes
					decode_imsi_paging(pdsch_res[tb].payload, result_length);
				}
				/*Unpack PDSCH msg to receive SDU, SDU and then decode RRC Connection Setup*/
				srsran::sch_pdu pdu(20, srslog::fetch_basic_logger("MAC"));
				pdu.init_rx(result_length, false);
				pdu.parse_packet(pdsch_res->payload);
				bool is_rrc_connection_setup = false;

				int subh_idx = 0;
				sch_subh sub_header[4];
				bool found_res = false;
				while (pdu.next() && !found_res)
				{
					if(pdu.get()->is_sdu()){
						int payload_length 	= pdu.get()->get_payload_size();
						uint8_t* sdu_ptr 	= pdu.get()->get_sdu_ptr();
						/* Decode RRC Connection Setup when found valid sdu from MAC pdu*/
						ltesniffer_ue_spec_config_t ue_config;
						int rrc_ret = decode_rrc_connection_setup(sdu_ptr, payload_length, &ue_config);
						if (rrc_ret == SRSRAN_SUCCESS){ //success means RRC Connection Setup
							is_rrc_connection_setup = true;
							ret =  UL_SNIFFER_FOUND_CON_SET;
							if (!mcs_tracking->check_default_config()){
								mcs_tracking->update_default_ue_config(ue_config);
								mcs_tracking->set_has_default_config();
							}
							mcs_tracking->update_ue_config_rnti(cur_rnti, ue_config);
						}
					}else{
						sub_header[subh_idx] = *pdu.get();
						subh_idx++;
					}
					if(is_rrc_connection_setup && (api_mode == 0 || api_mode == 3)){
						for (int h = 0; h < 4 && !found_res; h++){
							if ((dl_sch_lcid)sub_header[h].lcid_value() == dl_sch_lcid::CON_RES_ID){
								uint64_t contention_resolution = sub_header[h].get_con_res_id();
								std::stringstream ss;
								ss << std::hex << contention_resolution;
								std::string temp_con_res_str = ss.str();
								std::string con_res_str = temp_con_res_str.substr(3,8);
								// printf("[API] SF: %d-%d Found RRC Connection Setup, Contention Resolution = %s, RNTI = %d \n",
								// 		tti/10, tti%10, con_res_str.c_str(), cur_rnti);
								print_api_dl( tti, cur_rnti, ID_CON_RES , con_res_str, MSG_CON_SET);
								mcs_tracking->increase_nof_api_msg();
								found_res = true;
							}
						}
						//write_pcap(RNTI_name, pdsch_res[tb].payload, result_length, cur_rnti, tti, false);
						pcapwriter->write_dl_crnti_api(pdsch_res[tb].payload, result_length, cur_rnti, true, tti, false);
					}
				}
			}
		}
		return ret;
	} else {
		//nothing
	}
}

int PDSCH_Decoder::decode_ul_mode(uint32_t rnti, std::vector<DL_Sniffer_rar_result> *rar_result){
	uint32_t tti = sfn * 10 + sf_idx;
	for (auto decoding_mem:(*ran_dl_collection)){
		/* set up variable*/
		int harq_ret[SRSRAN_MAX_CODEWORDS] = {DL_SNIFFER_NEW_TX, DL_SNIFFER_NEW_TX};
		srsran_dci_dl_t *cur_ran_dci_dl = decoding_mem.ran_dci_dl.get();
		uint32_t cur_rnti = decoding_mem.rnti;
		srsran_dci_format_t cur_format = decoding_mem.format;
		std::string RNTI_name;
		if((cur_rnti >= SRSRAN_RARNTI_START) && (cur_rnti <= SRSRAN_RARNTI_END)){
			srsran_pdsch_grant_t *cur_grant;
			cur_grant = decoding_mem.ran_pdsch_grant.get();

			for (uint32_t tb = 0; tb < SRSRAN_MAX_CODEWORDS; tb++) {
				pdsch_res[tb].crc     = false;
			}

			bool tb_en[SRSRAN_MAX_CODEWORDS]{cur_grant->tb[0].enabled, cur_grant->tb[1].enabled};
			int mimo_ret = SRSRAN_SUCCESS;
			bool unknown_mcs;

            /*try only 64QAM table*/
			DL_Sniffer_rar_result result;
			int ret = run_rar_decode(cur_format, cur_ran_dci_dl, cur_grant, cur_rnti, result);
            if (ret == SRSRAN_SUCCESS){
                rar_result->push_back(std::move(result));
            } else{
                //do nothing
            }
		}else if (cur_rnti == rnti || rnti == 0 || (cur_rnti > SRSRAN_RARNTI_END)) {
			/* In the uplink sniffing mode, downlink sniffing function 
			/  only decodes PDSCH messages that were detected by DCI 1 and 1A
			*/
			if ((cur_format == SRSRAN_DCI_FORMAT1 || cur_format == SRSRAN_DCI_FORMAT1A)&&(cur_rnti!=SRSRAN_SIRNTI))
			{
				if (cur_rnti == SRSRAN_SIRNTI) { 
					RNTI_name = "SI_RNTI";
				}
				else if (cur_rnti == SRSRAN_PRNTI) {
					RNTI_name = "P_RNTI";
					//std::cout << "P_RNTI" << std::endl;
				}
				else if ((cur_rnti > SRSRAN_RARNTI_START) && (cur_rnti < SRSRAN_RARNTI_END)) { 
					RNTI_name = "RA_RNTI";
				}
				else {
					RNTI_name = "C_RNTI" ;
				}
				//mcs
				srsran_pdsch_grant_t *cur_grant;
				srsran_pdsch_grant_t *cur_grant256;
				cur_grant = decoding_mem.ran_pdsch_grant.get();
				cur_grant256 = decoding_mem.ran_pdsch_grant_256.get();

				for (uint32_t tb = 0; tb < SRSRAN_MAX_CODEWORDS; tb++) {
					pdsch_res[tb].crc     = false;
				}

				bool tb_en[SRSRAN_MAX_CODEWORDS]{cur_grant->tb[0].enabled, cur_grant->tb[1].enabled};
				int mimo_ret = SRSRAN_SUCCESS;
				bool unknown_mcs;
				/*Only uses 64QAM MCS table*/
				int ret = run_decode(mimo_ret, cur_format, cur_ran_dci_dl, cur_grant, cur_rnti, "64QAM table", RNTI_name, tti);
				if (ret == UL_SNIFFER_FOUND_CON_SET){
					found_con_ret = true;
				}
				// if (!pdsch_res[0].crc&&!pdsch_res[1].crc)
				// {
				// 	run_decode(mimo_ret, cur_format, cur_ran_dci_dl, cur_grant256, cur_rnti, "256QAM table");
				// }
			}

		}
	} //end of decoding loop

	if (found_con_ret == true){
		found_con_ret = false;
		return UL_SNIFFER_FOUND_CON_SET;
	}
	return SRSRAN_SUCCESS;
}

int PDSCH_Decoder::decode_SIB() //change to decode SIB
{
	uint32_t tti = sfn * 10 + sf_idx;
	for (auto decoding_mem:(*ran_dl_collection)){
		/* set up variable*/
		int harq_ret[SRSRAN_MAX_CODEWORDS] = {DL_SNIFFER_NEW_TX, DL_SNIFFER_NEW_TX};
		srsran_dci_dl_t *cur_ran_dci_dl = decoding_mem.ran_dci_dl.get();
		uint32_t cur_rnti = decoding_mem.rnti;
		srsran_dci_format_t cur_format = decoding_mem.format;
		std::string RNTI_name;
		if (cur_rnti == SRSRAN_SIRNTI) { 
			RNTI_name = "SI_RNTI";
			//mcs
			srsran_pdsch_grant_t *cur_grant;
			srsran_pdsch_grant_t *cur_grant256;
			if (decoding_mem.mcs_table == DL_SNIFFER_64QAM_TABLE)
			{
				cur_grant = decoding_mem.ran_pdsch_grant.get();
			} else if (decoding_mem.mcs_table == DL_SNIFFER_256QAM_TABLE){
				cur_grant = decoding_mem.ran_pdsch_grant_256.get();
			} else {
				cur_grant = decoding_mem.ran_pdsch_grant.get();
				cur_grant256 = decoding_mem.ran_pdsch_grant_256.get();
			}
			for (uint32_t tb = 0; tb < SRSRAN_MAX_CODEWORDS; tb++) {
				pdsch_res[tb].crc     = false;
			}

			int mimo_ret = SRSRAN_SUCCESS;
			//prepare decoding
			mimo_ret = dl_sniffer_config_mimo(&falcon_ue_dl->q->cell, cur_format, cur_ran_dci_dl, cur_grant);
			if (mimo_ret == SRSRAN_SUCCESS){
				/* config pdsch_cfg for decoding pdsch*/
				pdsch_cfg->grant = *cur_grant;
				pdsch_cfg->rnti = cur_rnti;
				
				for (int i = 0; i < SRSRAN_MAX_CODEWORDS; i++) {
					if (pdsch_cfg->grant.tb[i].enabled) {
						if (pdsch_cfg->grant.tb[i].rv < 0) {
							uint32_t k                = (sfn / 2) % 4;
							pdsch_cfg->grant.tb[i].rv = ((uint32_t)ceilf((float)1.5 * k)) % 4;
						}
						pdsch_cfg->softbuffers.rx[i] = buffer[i];
						srsran_softbuffer_rx_reset_tbs(pdsch_cfg->softbuffers.rx[i], (uint32_t)pdsch_cfg->grant.tb[i].tbs);
					}
				}

				//main function to decode
				if (pdsch_cfg->grant.tb[0].enabled||pdsch_cfg->grant.tb[1].enabled){
					if (srsran_ue_dl_decode_pdsch(falcon_ue_dl->q, dl_sf, pdsch_cfg, pdsch_res)) {
					ERROR("ERROR: Decoding PDSCH");
					}
				}
				//write pcap file
				for (uint32_t tb = 0; tb < SRSRAN_MAX_CODEWORDS; tb++) {
					if (pdsch_res[tb].crc){
						int result_length = pdsch_cfg->grant.tb[tb].tbs/8;

						/*Unpack SIB to get Uplink config from SIB2*/
						asn1::rrc::bcch_dl_sch_msg_s dlsch_msg;
						asn1::cbit_ref    dlsch_bref(pdsch_res[tb].payload, result_length);
						asn1::SRSASN_CODE err = dlsch_msg.unpack(dlsch_bref);
						if (err == asn1::SRSASN_SUCCESS){
							if (dlsch_msg.msg.c1().type() == asn1::rrc::bcch_dl_sch_msg_type_c::c1_c_::types::sib_type1){
								// do nothing
							} else {
								asn1::rrc::sys_info_r8_ies_s::sib_type_and_info_l_& sib_list =
									dlsch_msg.msg.c1().sys_info().crit_exts.sys_info_r8().sib_type_and_info;
								for (uint32_t i = 0; i < sib_list.size(); ++i) {
									/*SIB2*/
									if (sib_list[i].type().value==asn1::rrc::sib_info_item_c::types::sib2){
										sib2 = sib_list[i].sib2();
										/*Write pcap*/
										write_pcap(RNTI_name, pdsch_res[tb].payload, result_length, cur_rnti, tti, harq_ret);
										return DL_SNIFFER_SIB2_SUCCESS;
									}
								}
							}
						}

					}
				}
			} else {
				//nothing
			}
		}
	} //end of decoding loop

	return SRSRAN_SUCCESS;
}

int PDSCH_Decoder::decode_mac_ce(uint32_t rnti){
	uint32_t tti = sfn * 10 + sf_idx;
	for (auto decoding_mem:(*ran_dl_collection)){
		/* set up variable*/
		int harq_ret[SRSRAN_MAX_CODEWORDS] = {DL_SNIFFER_NEW_TX, DL_SNIFFER_NEW_TX};
		srsran_dci_dl_t *cur_ran_dci_dl = decoding_mem.ran_dci_dl.get();
		uint32_t cur_rnti = decoding_mem.rnti;
		srsran_dci_format_t cur_format = decoding_mem.format;
		std::string RNTI_name;
		if (cur_rnti == rnti) { 
			RNTI_name = "C_RNTI";
			//mcs
			srsran_pdsch_grant_t *cur_grant;
			srsran_pdsch_grant_t *cur_grant256;
			cur_grant = decoding_mem.ran_pdsch_grant.get();
			cur_grant256 = decoding_mem.ran_pdsch_grant_256.get();

			for (uint32_t tb = 0; tb < SRSRAN_MAX_CODEWORDS; tb++) {
				pdsch_res[tb].crc     = false;
			}

			bool tb_en[SRSRAN_MAX_CODEWORDS]{cur_grant->tb[0].enabled, cur_grant->tb[1].enabled};
			int mimo_ret = SRSRAN_SUCCESS;
			bool unknown_mcs;
			run_decode(mimo_ret, cur_format, cur_ran_dci_dl, cur_grant, cur_rnti, "64QAM table", RNTI_name, tti);
			if (!pdsch_res[0].crc&&!pdsch_res[1].crc)
			{
				run_decode(mimo_ret, cur_format, cur_ran_dci_dl, cur_grant256, cur_rnti, "256QAM table", RNTI_name, tti);
			}
		}
	} //end of decoding loop

	return SRSRAN_SUCCESS;
} 

void PDSCH_Decoder::write_pcap(std::string RNTI_name, uint8_t *pdu, uint32_t pdu_len_bytes, uint16_t crnti, uint32_t tti, bool retx){
	
	if (RNTI_name == "SI_RNTI"){
		pcapwriter->write_dl_sirnti(pdu, pdu_len_bytes, true, tti);

	}else if (RNTI_name == "P_RNTI"){
		pcapwriter->write_dl_pch(pdu, pdu_len_bytes, true, tti);

	}else if (RNTI_name == "RA_RNTI"){
		pcapwriter->write_dl_ranti(pdu, pdu_len_bytes, crnti, true, tti);

	} else{ //CRNTI
		pcapwriter->write_dl_crnti(pdu, pdu_len_bytes, crnti, true, tti, retx);
	}

}

int PDSCH_Decoder::unpack_rar_response_ul_mode(uint8_t *payload, int length, DL_Sniffer_rar_result &result){
	srsran::rar_pdu rar_pdu_msg;
	rar_pdu_msg.init_rx(length);
	if (rar_pdu_msg.parse_packet(payload) == SRSRAN_SUCCESS) //T_note: check here
	{
		while (rar_pdu_msg.next())
		{
			result.t_crnti = rar_pdu_msg.get()->get_temp_crnti();
			result.ta = rar_pdu_msg.get()->get_ta_cmd();
			rar_pdu_msg.get()->get_sched_grant(result.grant);
			srsran_dci_ul_t        dci_ul;
			srsran_dci_rar_grant_t rar_grant;
			ul_sniffer_dci_rar_unpack(result.grant, &rar_grant);
			ul_sniffer_dci_rar_to_ul_dci(&falcon_ue_dl->q->cell, &rar_grant, &dci_ul);
			dci_ul.rnti = result.t_crnti;
			dci_ul.format = SRSRAN_DCI_FORMAT_RAR;
			result.ran_dci_ul = dci_ul;

			srsran_ul_sf_cfg_t ul_sf;
			bzero(&ul_sf, sizeof(srsran_ul_sf_cfg_t));
			ul_sf.shortened = false;
			ul_sf.tdd_config = dl_sf->tdd_config;
			ul_sf.tti = dl_sf->tti;
			ul_sniffer_ra_ul_dci_to_grant(&falcon_ue_dl->q->cell, &ul_sf, &hopping_cfg, &dci_ul, &result.ran_ul_grant);
			rntiManager.activateAndRefresh(result.t_crnti, 0, ActivationReason::RM_ACT_RAR); //add RNTI in RAR response to active list
			// std::cout << " RAR: " << "TA = " << result.ta;
			// std::cout << " -- T-CRNTI: " << result.t_crnti;
			// std::cout << " -- GRANT: ";
			// for (int g = 0; g < 20; g++){
			// 	std::cout << unsigned(result.grant[g]) << " ";
			// }
			// std::cout << std::endl;
			return SRSRAN_SUCCESS;
		}
	}
}

int PDSCH_Decoder::run_rar_decode(srsran_dci_format_t cur_format,
                                  srsran_dci_dl_t *cur_ran_dci_dl,
                                  srsran_pdsch_grant_t *cur_grant,
                                  uint32_t cur_rnti,
                                  DL_Sniffer_rar_result &result)
{
    //std::cout << "Runing table: " << table << std::endl;
	std::string RNTI_name = "RA_RNTI";
	uint32_t tti = sfn*10 + sf_idx;
    int mimo_ret = SRSRAN_SUCCESS;
	mimo_ret = dl_sniffer_config_mimo(&falcon_ue_dl->q->cell, cur_format, cur_ran_dci_dl, cur_grant);
	if (mimo_ret == SRSRAN_SUCCESS){
		/* config pdsch_cfg for decoding pdsch*/
		pdsch_cfg->grant = *cur_grant; //check again here
		pdsch_cfg->rnti = cur_rnti;
		
		for (int i = 0; i < SRSRAN_MAX_CODEWORDS; i++) {
			if (pdsch_cfg->grant.tb[i].enabled) {
				if (pdsch_cfg->grant.tb[i].rv < 0) {
					uint32_t k                = (sfn / 2) % 4;
					pdsch_cfg->grant.tb[i].rv = ((uint32_t)ceilf((float)1.5 * k)) % 4;
				}
				pdsch_cfg->softbuffers.rx[i] = buffer[i];
				srsran_softbuffer_rx_reset_tbs(pdsch_cfg->softbuffers.rx[i], (uint32_t)pdsch_cfg->grant.tb[i].tbs);
			}
		}
        //std::cout << "Runing table: " << table << " -- 0" << std::endl;
		//main function to decode
		if (pdsch_cfg->grant.tb[0].enabled||pdsch_cfg->grant.tb[1].enabled){
            //std::cout << "Runing table: " << table << " -- 1" << std::endl;
			if (srsran_ue_dl_decode_pdsch(falcon_ue_dl->q, dl_sf, pdsch_cfg, pdsch_res)) {
			    ERROR("ERROR: Decoding PDSCH");
			}
		}
		for (uint32_t tb = 0; tb < SRSRAN_MAX_CODEWORDS; tb++) {
			if (pdsch_res[tb].crc){
				int result_length = pdsch_cfg->grant.tb[tb].tbs/8;
                write_pcap(RNTI_name, pdsch_res[tb].payload, result_length, cur_rnti, tti, false);

				/*Unpack PDSCH msg to receive rar*/
                std::time_t epoch = std::time(nullptr);
                char* time = std::asctime(std::localtime(&epoch));
                std::string time_str;
                for (int idx = 11; idx < 19; idx++){
                    time_str.push_back(time[idx]);
                }
                time_str = "[" + time_str + "]";
                unpack_rar_response_ul_mode(pdsch_res->payload, result_length, result);
				return SRSASN_SUCCESS;
			}
		}
        return SRSRAN_ERROR;
	} else {
		std::cout << "Config MIMO wrong: " << mimo_ret << std::endl;
        return SRSRAN_ERROR;
	}
}


int PDSCH_Decoder::decode_rar(DL_Sniffer_rar_result &result){
	uint32_t tti = sfn * 10 + sf_idx;
	int ret = SRSRAN_ERROR;
	for (auto decoding_mem:(*ran_dl_collection)){
		/* set up variable*/
		int harq_ret[SRSRAN_MAX_CODEWORDS] = {DL_SNIFFER_NEW_TX, DL_SNIFFER_NEW_TX};
		srsran_dci_dl_t *cur_ran_dci_dl = decoding_mem.ran_dci_dl.get();
		uint32_t cur_rnti = decoding_mem.rnti;
		srsran_dci_format_t cur_format = decoding_mem.format;
		std::string RNTI_name;
		if (cur_rnti > SRSRAN_RARNTI_START && cur_rnti < SRSRAN_RARNTI_END) { 
			//std::cout << "Decoding RNTI: " << rnti << std::endl;
			//mcs
			srsran_pdsch_grant_t *cur_grant;
			cur_grant = decoding_mem.ran_pdsch_grant.get();

			for (uint32_t tb = 0; tb < SRSRAN_MAX_CODEWORDS; tb++) {
				pdsch_res[tb].crc     = false;
			}

			bool tb_en[SRSRAN_MAX_CODEWORDS]{cur_grant->tb[0].enabled, cur_grant->tb[1].enabled};
			int mimo_ret = SRSRAN_SUCCESS;
			bool unknown_mcs;

            /*rar uses 64QAM table*/
			int decode_ret = run_rar_decode(cur_format, cur_ran_dci_dl, cur_grant, cur_rnti, result);
            if (decode_ret == SRSRAN_SUCCESS){
                ret = SRSRAN_SUCCESS;
            }
		}
	} //end of decoding loop

	return ret;
} 

void PDSCH_Decoder::unpack_rar_response_dl_mode(uint8_t *ptr, int result_length){
	srsran::rar_pdu rar_pdu_msg;
	rar_pdu_msg.init_rx(result_length);
	uint16_t t_crnti = 0;
	if (rar_pdu_msg.parse_packet(ptr) == SRSRAN_SUCCESS)
	{
		while (rar_pdu_msg.next())
		{
			t_crnti = rar_pdu_msg.get()->get_temp_crnti();
			clock_t cur_time = clock();
			mcs_tracking->update_rar_time_crnti(t_crnti, cur_time);
			rntiManager.activateAndRefresh(t_crnti, 0, ActivationReason::RM_ACT_RAR);
		}
	}
}

void print_dl_grant_dci(srsran_dci_dl_t &dl_dci, uint16_t tti, uint16_t rnti){
    std::cout << "[DCI] SF: " <<  tti/10 << ":" << tti%10 << "-RNTI: " << rnti << " -Format: " << dl_dci.format << " -MCS: " << dl_dci.tb[0].mcs_idx<< \
    " -RV: " << dl_dci.tb[0].rv  << std::endl;
}

int PDSCH_Decoder::decode_dl_mode(){
    uint32_t tti = sfn * 10 + sf_idx;
    // printf("[%d] SF: %d-%d Nof_DCI = %d \n", idx, sfn, sf_idx, ran_dl_collection->size());
    for (auto decoding_mem:(*ran_dl_collection)){
        if (decoding_mem.ran_pdsch_grant->tb[0].tbs > 0 && decoding_mem.ran_dci_dl->rnti > 0 &&  		//only decode if packet length > 0 and rnti != 0, 
			!(nof_antenna == 1 && (decoding_mem.ran_pdsch_grant->nof_tb == 2 || decoding_mem.ran_pdsch_grant_256->nof_tb == 2))){ //only decode DCI with 2 TB if having 2 RX antennas, 
			if (decoding_mem.ran_dci_dl->tb[0].rv < 0){
				// print_dl_grant_dci(*decoding_mem.ran_dci_dl.get(), tti, decoding_mem.rnti);
				if (decoding_mem.rnti == 65535){ // on some basestations, SIB1 has DCI 1C with rv index = -1, change it to 0 to decode?
					decoding_mem.ran_pdsch_grant->tb[0].rv = 0;
				}
			}
            /* set up variable*/
            int harq_ret[SRSRAN_MAX_CODEWORDS] 	= {DL_SNIFFER_NEW_TX, DL_SNIFFER_NEW_TX};
            srsran_dci_dl_t 	*cur_ran_dci_dl = decoding_mem.ran_dci_dl.get();
            uint32_t 			cur_rnti 		= decoding_mem.rnti;
            srsran_dci_format_t cur_format 		= decoding_mem.format;
            std::string 		RNTI_name 		= rnti_name(cur_rnti);

            //mcs
            srsran_pdsch_grant_t *cur_grant;
            srsran_pdsch_grant_t *cur_grant256;
            if (decoding_mem.mcs_table == DL_SNIFFER_64QAM_TABLE)
            {
                cur_grant = decoding_mem.ran_pdsch_grant.get();
            } else if (decoding_mem.mcs_table == DL_SNIFFER_256QAM_TABLE){
                cur_grant = decoding_mem.ran_pdsch_grant_256.get();
            } else {
                cur_grant = decoding_mem.ran_pdsch_grant.get();
                cur_grant256 = decoding_mem.ran_pdsch_grant_256.get();
            }
            for (uint32_t tb = 0; tb < SRSRAN_MAX_CODEWORDS; tb++) {
                pdsch_res[tb].crc     = false;
            }
			ltesniffer_ue_spec_config_t ue_config = mcs_tracking->get_ue_config_rnti(cur_rnti); //find p_a from database
			pdsch_cfg->p_a = ue_config.p_a; //update p_a from database
            bool tb_en[SRSRAN_MAX_CODEWORDS]{cur_grant->tb[0].enabled, cur_grant->tb[1].enabled};
            int mimo_ret = SRSRAN_SUCCESS;
            bool unknown_mcs;

            if ((decoding_mem.mcs_table == DL_SNIFFER_64QAM_TABLE)||(decoding_mem.mcs_table == DL_SNIFFER_256QAM_TABLE))
            {
                //prepare decoding
                unknown_mcs = false;
                mimo_ret = dl_sniffer_config_mimo(&falcon_ue_dl->q->cell, cur_format, cur_ran_dci_dl, cur_grant);
                if (mimo_ret == SRSRAN_SUCCESS){
                    /* config pdsch_cfg for decoding pdsch*/
                    pdsch_cfg->grant = *cur_grant; //check again here
                    pdsch_cfg->rnti = cur_rnti;
                    
                    for (int i = 0; i < SRSRAN_MAX_CODEWORDS; i++) {
                        if (pdsch_cfg->grant.tb[i].enabled) {
                            dl_sniffer_harq_grant_t cur_harq_grant = {};
                            cur_harq_grant.last_decoded = false;
                            cur_harq_grant.ndi = cur_ran_dci_dl->tb[i].ndi;
                            cur_harq_grant.ndi_present = true;
                            cur_harq_grant.rv = cur_ran_dci_dl->tb[i].rv;
                            cur_harq_grant.tbs = cur_grant->tb[i].tbs;
                            cur_harq_grant.is_first_transmission = false;

                            if (harq_mode && RNTI_name == "C_RNTI"){
                                /*Check is reTX or new TX*/
                                harq_ret[i] = harq->is_retransmission(cur_rnti, cur_ran_dci_dl->pid, i, cur_harq_grant, sfn, sf_idx);

                                switch (harq_ret[i]){
                                    case DL_SNIFFER_NEW_TX:
                                        pdsch_cfg->softbuffers.rx[i] = harq->getHARQBuffer(cur_rnti, cur_ran_dci_dl->pid, i);
                                        srsran_softbuffer_rx_reset_tbs(pdsch_cfg->softbuffers.rx[i], (uint32_t)pdsch_cfg->grant.tb[i].tbs);
                                        break;
                                    case DL_SNIFFER_HARQ_FULL_BUFFER:
                                        pdsch_cfg->softbuffers.rx[i] = buffer[i];
                                        srsran_softbuffer_rx_reset_tbs(pdsch_cfg->softbuffers.rx[i], (uint32_t)pdsch_cfg->grant.tb[i].tbs);
                                        break;
                                    case DL_SNIFFER_DECODED:
                                        pdsch_cfg->grant.tb[i].enabled = false;
                                        break;
                                    case DL_SNIFFER_RE_TX:
                                        pdsch_cfg->softbuffers.rx[i] = harq->getHARQBuffer(cur_rnti, cur_ran_dci_dl->pid, i);
                                        break;
                                    case DL_SNIFFER_HARQ_BUSY:
                                        pdsch_cfg->softbuffers.rx[i] = buffer[i];
                                        srsran_softbuffer_rx_reset_tbs(pdsch_cfg->softbuffers.rx[i], (uint32_t)pdsch_cfg->grant.tb[i].tbs);
                                        break;
                                    default:
                                        pdsch_cfg->softbuffers.rx[i] = buffer[i];
                                        srsran_softbuffer_rx_reset_tbs(pdsch_cfg->softbuffers.rx[i], (uint32_t)pdsch_cfg->grant.tb[i].tbs);
                                        break;
                                }
                            } else {
                                pdsch_cfg->softbuffers.rx[i] = buffer[i];
                                srsran_softbuffer_rx_reset_tbs(pdsch_cfg->softbuffers.rx[i], (uint32_t)pdsch_cfg->grant.tb[i].tbs);
                            }
                        }
                    }

                    //main function to decode
                    if (pdsch_cfg->grant.tb[0].enabled||pdsch_cfg->grant.tb[1].enabled){
                        if (srsran_ue_dl_decode_pdsch(falcon_ue_dl->q, dl_sf, pdsch_cfg, pdsch_res)) {
                            ERROR("ERROR: Decoding PDSCH");
                        }
                    }

                    /* Update HARQ buffer*/
                    for (int i = 0; i < SRSRAN_MAX_CODEWORDS; i++){
                        if (pdsch_cfg->grant.tb[i].enabled && harq_mode){
                            dl_sniffer_harq_grant_t cur_harq_grant = {};
                            cur_harq_grant.last_decoded         = pdsch_res[i].crc;
                            cur_harq_grant.ndi                  = cur_ran_dci_dl->tb[i].ndi;
                            cur_harq_grant.ndi_present          = true;
                            cur_harq_grant.rv                   = cur_ran_dci_dl->tb[i].rv;
                            cur_harq_grant.tbs                  = cur_grant->tb[i].tbs;
                            cur_harq_grant.is_first_transmission = false;
                            if ((RNTI_name == "C_RNTI")&&(harq_ret[i] == DL_SNIFFER_NEW_TX||harq_ret[i] == DL_SNIFFER_RE_TX)&&harq_mode){
                                harq->updateHARQRNTI(cur_rnti, cur_ran_dci_dl->pid, i, sfn, sf_idx, cur_harq_grant);
                            }
                        }
                    }

                    //write pcap file and unpack RAR, RRC Connection Setup
                    for (uint32_t tb = 0; tb < SRSRAN_MAX_CODEWORDS; tb++) {
                        int nof_tb = 1;
                        if (cur_grant->tb[1].enabled == true){
                            nof_tb = 2;
                        }
                        int result_length = pdsch_cfg->grant.tb[tb].tbs/8;
                        std::string dci_fm = dci_format(cur_format);
                        std::string mod = mod_sche(cur_grant->tb[tb].mod);
                        std::string table_name = decoding_mem.mcs_table?("256"):("64");
                        if (pdsch_res[tb].crc && result_length > 0){
                            write_pcap(RNTI_name, pdsch_res[tb].payload, result_length, cur_rnti, tti, 0);
							if (RNTI_name == "RA_RNTI"){
								unpack_rar_response_dl_mode(pdsch_res[tb].payload, result_length);
							}
							if (RNTI_name == "C_RNTI"){
								/*Unpack PDSCH msg to receive SDU, SDU and then decode RRC Connection Setup*/
								srsran::sch_pdu pdu(20, srslog::fetch_basic_logger("MAC"));
								pdu.init_rx(result_length, false);
								pdu.parse_packet(pdsch_res[tb].payload);
								bool is_rrc_connection_setup = false;
								int subh_idx = 0;
								sch_subh sub_header[4];
								while (pdu.next())
								{
									if(pdu.get()->is_sdu()){
										int payload_length = pdu.get()->get_payload_size();
										uint8_t* sdu_ptr = pdu.get()->get_sdu_ptr();
										/* Decode RRC Connection Setup to obtain UE Specific Configuration*/
										ltesniffer_ue_spec_config_t ue_config = {};
										int rrc_ret = decode_rrc_connection_setup(sdu_ptr, payload_length, &ue_config);
										if (rrc_ret == SRSRAN_SUCCESS){ //success means RRC Connection Setup
											if (!mcs_tracking->check_default_config()){
												mcs_tracking->update_default_ue_config(ue_config);
												mcs_tracking->set_has_default_config();
											}
											mcs_tracking->update_ue_config_rnti(cur_rnti, ue_config);
										}
									}
								}
							}
                        }
                        if (cur_rnti != 65535 && cur_grant->tb[tb].enabled && (target_rnti == 0 || cur_rnti == target_rnti) && en_debug){
                            print_debug_dl(table_name , tti, decoding_mem.rnti, dci_fm, mod, decoding_mem.ran_dci_dl->tb[0].mcs_idx, harq_ret[tb], 
                                            nof_tb, result_length, pdsch_res[tb].crc, &falcon_ue_dl->q->chest_res);
                        }
                    }
                } else {
                    //nothing
                }
            } else{ // If dont know MCS table, try both tables
                /*Try 64QAM table first*/
                unknown_mcs = true;
                mimo_ret = dl_sniffer_config_mimo(&falcon_ue_dl->q->cell, cur_format, cur_ran_dci_dl, cur_grant);
                if (mimo_ret == SRSRAN_SUCCESS){
                    /* config pdsch_cfg for decoding pdsch*/
                    pdsch_cfg->grant = *cur_grant; //check again here
                    pdsch_cfg->rnti = cur_rnti;

                    for (int i = 0; i < SRSRAN_MAX_CODEWORDS; i++) {
                        if (pdsch_cfg->grant.tb[i].enabled) {
                            pdsch_cfg->softbuffers.rx[i] = buffer[i];
                            srsran_softbuffer_rx_reset_tbs(pdsch_cfg->softbuffers.rx[i], (uint32_t)pdsch_cfg->grant.tb[i].tbs);
                        }
                    }

                    /*main function to decode */
                    if (srsran_ue_dl_decode_pdsch(falcon_ue_dl->q, dl_sf, pdsch_cfg, pdsch_res)) {
                        ERROR("ERROR: Decoding PDSCH");
                    }

                    //write pcap file
                    for (uint32_t tb = 0; tb < SRSRAN_MAX_CODEWORDS; tb++) {
                        int nof_tb = 1;
                        if (cur_grant->tb[1].enabled == true){
                            nof_tb = 2;
                        }
                        int result_length  = pdsch_cfg->grant.tb[tb].tbs/8;
                        std::string dci_fm = dci_format(cur_format);
                        std::string mod    = mod_sche(cur_grant->tb[tb].mod);
                        if (pdsch_res[tb].crc && result_length > 0){
                            write_pcap(RNTI_name, pdsch_res[tb].payload, result_length, cur_rnti, tti, 0);
							if (RNTI_name == "RA_RNTI"){
								unpack_rar_response_dl_mode(pdsch_res[tb].payload, result_length);
							}
							if (RNTI_name == "C_RNTI"){
								/*Unpack PDSCH msg to receive SDU, SDU and then decode RRC Connection Setup*/
								srsran::sch_pdu pdu(20, srslog::fetch_basic_logger("MAC"));
								pdu.init_rx(result_length, false);
								pdu.parse_packet(pdsch_res[tb].payload);
								bool is_rrc_connection_setup = false;
								int subh_idx = 0;
								sch_subh sub_header[4];
								while (pdu.next())
								{
									if(pdu.get()->is_sdu()){
										int payload_length = pdu.get()->get_payload_size();
										uint8_t* sdu_ptr = pdu.get()->get_sdu_ptr();
										/* Decode RRC Connection Setup to obtain UE Specific Configuration*/
										ltesniffer_ue_spec_config_t ue_config = {};
										int rrc_ret = decode_rrc_connection_setup(sdu_ptr, payload_length, &ue_config);
										if (rrc_ret == SRSRAN_SUCCESS){ //success means RRC Connection Setup
											if (!mcs_tracking->check_default_config()){
												mcs_tracking->update_default_ue_config(ue_config);
												mcs_tracking->set_has_default_config();
											}
											mcs_tracking->update_ue_config_rnti(cur_rnti, ue_config);
										}
									}
								}
							}
                            //update mcs table to database only when mcs_idx > 0 (0 index is overlap in both tables):
                            if (cur_ran_dci_dl->tb[tb].mcs_idx > 0 &&cur_ran_dci_dl->tb[tb].mcs_idx < 29 && decoding_mem.format > SRSRAN_DCI_FORMAT1A && result_length > 0){
                                mcs_tracking->update_RNTI_dl(cur_rnti, DL_SNIFFER_64QAM_TABLE);
                            }
                        }
                        if (cur_rnti != 65535 && cur_grant->tb[tb].enabled && (target_rnti == 0 || cur_rnti == target_rnti) && en_debug){
                            print_debug_dl("Unkown64" ,tti, decoding_mem.rnti, dci_fm, mod, decoding_mem.ran_dci_dl->tb[0].mcs_idx, harq_ret[tb], 
                                                nof_tb, result_length, pdsch_res[tb].crc, &falcon_ue_dl->q->chest_res);                
                            }
                        }
                } else{
                    //nothing
                }

                // if 64QAM table failed, try 256QAM table:
                if (!pdsch_res[0].crc && !pdsch_res[1].crc && mimo_ret == SRSRAN_SUCCESS){
                    pdsch_cfg->use_tbs_index_alt = true;
                    //prepare decoding
                    mimo_ret = dl_sniffer_config_mimo(&falcon_ue_dl->q->cell, cur_format, cur_ran_dci_dl, cur_grant256);
                    if (mimo_ret == SRSRAN_SUCCESS){
                        /* config pdsch_cfg for decoding pdsch*/
                        pdsch_cfg->grant = *cur_grant256; //check again here
                        pdsch_cfg->rnti = cur_rnti;

                        for (int i = 0; i < SRSRAN_MAX_CODEWORDS; i++) {
                            if (pdsch_cfg->grant.tb[i].enabled) {
                                pdsch_cfg->softbuffers.rx[i] = buffer[i];
                                srsran_softbuffer_rx_reset_tbs(pdsch_cfg->softbuffers.rx[i], (uint32_t)pdsch_cfg->grant.tb[i].tbs);
                            }
                        }
                        
                        //main function to decode
                        if (srsran_ue_dl_decode_pdsch(falcon_ue_dl->q, dl_sf, pdsch_cfg, pdsch_res)) {
                            ERROR("ERROR: Decoding PDSCH");
                        }
                        //write pcap file
                        for (uint32_t tb = 0; tb < SRSRAN_MAX_CODEWORDS; tb++) {
                            int nof_tb = 1;
                            if (cur_grant256->tb[1].enabled == true){
                                nof_tb = 2;
                            }
                            int result_length = pdsch_cfg->grant.tb[tb].tbs/8;
                            std::string dci_fm = dci_format(cur_format);
                            std::string mod = mod_sche(cur_grant256->tb[tb].mod);
                            if (pdsch_res[tb].crc && result_length > 0){
                                write_pcap(RNTI_name, pdsch_res[tb].payload, result_length, cur_rnti, tti, 0);
                                //update mcs table to database when mcs < 28 because 256QAM table:
								//cur_ran_dci_dl->tb[tb].mcs_idx > 0 && cur_ran_dci_dl->tb[tb].mcs_idx < 28 && decoding_mem.format > SRSRAN_DCI_FORMAT1A && result_length > 0
                                if (cur_ran_dci_dl->tb[tb].mcs_idx > 0 && cur_ran_dci_dl->tb[tb].mcs_idx < 28 && decoding_mem.format > SRSRAN_DCI_FORMAT1A && result_length > 0){
                                    mcs_tracking->update_RNTI_dl(cur_rnti, DL_SNIFFER_256QAM_TABLE);
                                }
                            }
                            if (cur_rnti != 65535 && cur_grant256->tb[tb].enabled && (target_rnti == 0 || cur_rnti == target_rnti) && en_debug){
                                print_debug_dl( "Unkown256" ,tti, decoding_mem.rnti, dci_fm, mod, decoding_mem.ran_dci_dl->tb[0].mcs_idx, harq_ret[tb], 
                                            nof_tb, result_length, pdsch_res[tb].crc, &falcon_ue_dl->q->chest_res);
                            }
                        }
                    } else {
                        // nothing
                    }
                }
                for (int j = 0; j < SRSRAN_MAX_CODEWORDS; j++){
                    if (tb_en[j]){
                        INFO("[PDSCH] Decoding Unknown table tb[%d]: RNTI: %d, format: %d, mcs_idx: %d -- pid: %d -- pinfo: %d -- sf: %d-%d --",
                                            j, cur_rnti, decoding_mem.format, cur_grant->tb[j].mcs_idx, cur_ran_dci_dl->pid, cur_ran_dci_dl->pinfo, sfn, sf_idx);
                        if ((pdsch_res[j].crc)){
                            INFO("\033[0;32m SUCCESS \n");
                            INFO("\033[0m");
                        } else{
                            INFO("\033[0;31m FAILED \n");
                            INFO("\033[0m");
                        }
                    }
                }
                
            }
            bool success[SRSRAN_MAX_CODEWORDS]{pdsch_res[0].crc, pdsch_res[1].crc};

            //update statistic
            if (RNTI_name == "C_RNTI" && mcs_tracking_mode){ //T_Note: changed for debuging && mimo_ret == SRSRAN_SUCCESS||| && decoding_mem.format > SRSRAN_DCI_FORMAT1A
                srsran_pdsch_grant_t *statistic_grant;
                if (decoding_mem.mcs_table == DL_SNIFFER_64QAM_TABLE){
                    statistic_grant = decoding_mem.ran_pdsch_grant.get();
                } else if (decoding_mem.mcs_table == DL_SNIFFER_256QAM_TABLE){
                    statistic_grant = decoding_mem.ran_pdsch_grant_256.get();
                } else {
                    statistic_grant = decoding_mem.ran_pdsch_grant.get();
                }
                mcs_tracking->update_statistic_dl(cur_rnti, tb_en, harq_ret, success, decoding_mem, mimo_ret, statistic_grant);
                
            }
            bool wrong_detect = (mimo_ret == SRSRAN_SUCCESS)?true:false;
            std::time_t cur_time = std::time(nullptr);
            //mcs_tracking->write_dci_to_file(cur_time, tti/10, tti%10, cur_rnti, cur_format, wrong_detect);
        }

    } //end of decoding loop
    
    return SRSRAN_SUCCESS;
}
void PDSCH_Decoder::print_debug_dl(	std::string name,
									int tti,
									uint16_t rnti,
									std::string format,
									std::string mod,
									int mcs_idx,
									int retx,
									int nof_tb,
									int length, 
									bool result,
									srsran_chest_dl_res_t* ce_res)
{
    std::cout << std::left << std::setw(9) << name;
    std::cout << "SF:" << std::left << std::setw(4) << tti/10 << "-" << tti%10;
    // std::cout << "[" << std::left << std::setw(2) << idx  << "]";
    std::cout << GREEN << " -- RNTI: " << std::left << std::setw(5) << rnti << RESET;
    std::cout << WHITE << " -- DCI: " << std::left << std::setw(4) << format << RESET;
    std::cout << YELLOW << " -- Mod: " << std::left << std::setw(6) << mod << RESET;
    std::cout << " -- MCS: " << std::left << std::setw(3) << mcs_idx;
    // std::string re_tx = retx?(" -- reTX"):(" -- NewTX");
    // std::cout << RED << std::left << std::setw(9) << re_tx << RESET;
    std::cout << CYAN << " -- nof_TB: " << std::left << pdsch_cfg->grant.nof_tb << RESET;
    std::cout << BLUE << " -- Byte: " << std::left << std::setw(5) << length << RESET;
    // std::cout << std::setprecision(2) << GREEN << " -- rsrp: " << ce_res->rsrp_dbm << " --rsrq: " \
    //     << ce_res->rsrq_db << " --SNR: " << ce_res->snr_db << " --CFO: " << ce_res->cfo << RESET;
    std::cout << " -- Antenna SNR: " << std::left << std::setw(4) << ce_res->snr_ant_port_db[0][0] \
                                           << "|" << std::setw(4) << ce_res->snr_ant_port_db[1][1] << RESET;
    std::cout << " -- SNR: " << std::left << std::setprecision(3) << std::setw(5) << ce_res->snr_db << RESET;
    std::cout << RESET << " -- Result: ";
    if (result){
        std::cout << std::left << std::setw(8) << GREEN << "SUCCESS";
    } else{
        std::cout << std::left << std::setw(8) << RED   << "FAILED";
    }
    std::cout << RESET<< std::endl;
}

std::string PDSCH_Decoder::dci_format(int format)
{
    switch (format)
    {
    case 0:
        return "0";
        break;
    case 1:
        return "1";
        break;
    case 2:
        return "1A";
        break;
    case 3:
        return "1B";
        break;
    case 4:
        return "1C";
        break;
    case 5:
        return "1D";
        break;
    case 6:
        return "2";
        break;
    case 7:
        return "2A";
        break;
    case 8:
        return "2B";
        break;
    default:
        return "UNKNOWN";
        break;
    }
}

std::string PDSCH_Decoder::mod_sche(int sche)
{
    switch (sche)
    {
    case 0:
        return "BPSK";
        break;
    case 1:
        return "QPSK";
        break;
    case 2:
        return "16QAM";
        break;
    case 3:
        return "64QAM";
        break;
    case 4:
        return "256QAM";
        break;
    default:
        return "UNKNOWN";
        break;
    }
}

std::string PDSCH_Decoder::rnti_name(uint16_t rnti){
    if (rnti == SRSRAN_SIRNTI) { 
        return "SI_RNTI";
    }else if (rnti == SRSRAN_PRNTI) {
        return "P_RNTI";
    }else if ((rnti > SRSRAN_RARNTI_START) && (rnti < SRSRAN_RARNTI_END)) { 
        return "RA_RNTI";
    }else {
        return "C_RNTI" ;
    }
}


std::string convert_id_name_dl(int id){
    switch (id)
    {
    case 0:
        return "RandomValue";
        break;
    case 1:
        return "TMSI";
        break;
    case 2:
        return "Contention Resolution";
        break;
    case 3:
        return "IMSI";
        break;
    default:
        return "-";
        break;
    }
}
std::string convert_msg_name_dl(int msg){
    switch (msg)
    {
    case 0:
        return "RRC Connection Request";
        break;
    case 1:
        return "RRC Connection Setup";
        break;
    case 2:
        return "Attach Request";
        break;
    case 3:
        return "Identity Response";
        break;
    case 4:
        return "UECapability";
        break;
    default:
        return "-";
        break;
    }
}
void PDSCH_Decoder::print_api_dl(uint32_t tti, uint16_t rnti, int id, std::string value, int msg){
    std::cout << std::left << std::setw(4) << tti/10 << "-" << std::left << std::setw(5) << tti%10;
    std::string id_name = convert_id_name_dl(id);
    std::cout << std::left << std::setw(26) << id_name;
    std::cout << std::left << std::setw(17) << value; 
	std::cout << std::left << std::setw(11) << rnti; 	
	std::string msg_name = convert_msg_name_dl(msg);
    std::cout << std::left << std::setw(25) << msg_name;
    std::cout << std::endl;
}