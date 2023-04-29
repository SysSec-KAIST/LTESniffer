/*
 * LTE DL_Snifer version 1.0
 * 
 */
#pragma once

#include "srsran/common/mac_pcap.h"
#include "srsran/common/pcap.h"
using namespace srsran;

class PcapWriter //not using now
{
public:
    PcapWriter(/* args */);
    ~PcapWriter();
    void pcap_set_up_file(std::string file_name);
    void pcap_close_file();
    void pcap_write_sib(uint8_t* pdu, uint32_t pdu_len_bytes, bool crc_ok, uint32_t tti, uint8_t cc_idx);
    void pcap_write_paging(uint8_t* pdu, uint32_t pdu_len_bytes, bool crc_ok, uint32_t tti, uint8_t cc_idx);
    void pcap_write_rar(uint8_t* pdu, uint32_t pdu_len_bytes, uint16_t ranti, bool crc_ok, uint32_t tti, uint8_t cc_idx);
    void pcap_write_crnti(uint8_t* pdu, uint32_t pdu_len_bytes, uint16_t crnti, bool crc_ok, uint32_t tti, uint8_t cc_idx);
private:
    std::string filename = "testpcap.pcap"; //random pcap file
    mac_pcap pcapwriter;
    std::mutex pcapmutex;
};

// Define a new class for not creating a new thread of pcap
class LTESniffer_pcap_writer
{
public:
    LTESniffer_pcap_writer() {enable_write=false; ue_id=0; pcap_file = NULL; };
    void enable(bool en);
    void open(const std::string filename, const std::string api_filename, uint32_t ue_id = 0);
    void close();

    void set_ue_id(uint16_t ue_id);

    void write_dl_crnti(uint8_t *pdu, uint32_t pdu_len_bytes, uint16_t crnti, bool crc_ok, uint32_t tti, bool retx); //C RNTI
    void write_dl_ranti(uint8_t *pdu, uint32_t pdu_len_bytes, uint16_t ranti, bool crc_ok, uint32_t tti);
    
    // SI and BCH only for DL 
    void write_dl_sirnti(uint8_t *pdu, uint32_t pdu_len_bytes, bool crc_ok, uint32_t tti); //SI
    void write_dl_bch(uint8_t *pdu, uint32_t pdu_len_bytes, bool crc_ok, uint32_t tti); // mib
    void write_dl_pch(uint8_t *pdu, uint32_t pdu_len_bytes, bool crc_ok, uint32_t tti); //paging
    void write_ul_crnti(uint8_t* pdu, uint32_t pdu_len_bytes, uint16_t crnti, uint32_t tti);
    
    /*Function for api*/
    void write_ul_crnti_api(uint8_t* pdu, uint32_t pdu_len_bytes, uint16_t crnti, uint32_t tti);
    void write_dl_crnti_api(uint8_t *pdu, uint32_t pdu_len_bytes, uint16_t crnti, bool crc_ok, uint32_t tti, bool retx); //C RNTI
    void write_dl_paging_api(uint8_t* pdu, uint32_t pdu_len_bytes, uint16_t rnti, bool crc_ok, uint32_t tti, bool retx);
private:
    std::mutex pcap_mutex;
    bool enable_write; 
    FILE *pcap_file;
    FILE *pcap_file_api;
    uint32_t ue_id;
    void pack_and_write(uint8_t* pdu, uint32_t pdu_len_bytes, uint32_t reTX, bool crc_ok, uint32_t tti,
                                uint16_t crnti_, uint8_t direction, uint8_t rnti_type);
    
    void pack_and_write_api(uint8_t* pdu, uint32_t pdu_len_bytes, uint32_t reTX, bool crc_ok, uint32_t tti,
                                uint16_t crnti_, uint8_t direction, uint8_t rnti_type);
};