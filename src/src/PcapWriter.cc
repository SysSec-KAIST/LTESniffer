#include "include/PcapWriter.h"

PcapWriter::PcapWriter(/* args */)
{

}

PcapWriter::~PcapWriter()
{
}

void PcapWriter::pcap_set_up_file(std::string file_name)
{
    filename = file_name;
    pcapwriter.open(filename);
}

void PcapWriter::pcap_close_file()
{
    pcapwriter.close();
}

void PcapWriter::pcap_write_sib(uint8_t* pdu, 
                               uint32_t pdu_len_bytes, 
                               bool crc_ok, 
                               uint32_t tti, 
                               uint8_t cc_idx)
{
    std::unique_lock<std::mutex> lock(pcapmutex);
    pcapwriter.write_dl_sirnti(pdu, pdu_len_bytes, crc_ok, tti, cc_idx);
    lock.unlock();
}

void PcapWriter::pcap_write_paging(uint8_t* pdu, 
                                  uint32_t pdu_len_bytes, 
                                  bool crc_ok, 
                                  uint32_t tti, 
                                  uint8_t cc_idx)
{
    std::unique_lock<std::mutex> lock(pcapmutex);
    pcapwriter.write_dl_pch(pdu, pdu_len_bytes, crc_ok, tti, cc_idx);
    lock.unlock();
}

void PcapWriter::pcap_write_rar(uint8_t* pdu, 
                               uint32_t pdu_len_bytes, 
                               uint16_t ranti, 
                               bool crc_ok, 
                               uint32_t tti, 
                               uint8_t cc_idx)
{
    std::unique_lock<std::mutex> lock(pcapmutex);
    pcapwriter.write_dl_ranti(pdu, pdu_len_bytes, ranti, crc_ok, tti, cc_idx);
    lock.unlock();
}

void PcapWriter::pcap_write_crnti(uint8_t* pdu, 
                                  uint32_t pdu_len_bytes, 
                                  uint16_t crnti, 
                                  bool crc_ok, 
                                  uint32_t tti, 
                                  uint8_t cc_idx)
{
    std::unique_lock<std::mutex> lock(pcapmutex);
    pcapwriter.write_dl_crnti(pdu, pdu_len_bytes, crnti, crc_ok, tti, cc_idx);
    lock.unlock();
}


//New class:
void LTESniffer_pcap_writer::enable(bool en)
{
  enable_write = true; 
}
void LTESniffer_pcap_writer::open(const std::string filename, const std::string api_filename, uint32_t ue_id)
{
  pcap_file       = DLT_PCAP_Open(MAC_LTE_DLT, filename.c_str());
  pcap_file_api   = DLT_PCAP_Open(MAC_LTE_DLT, api_filename.c_str());
  this->ue_id     = ue_id;
  enable_write    = true;
}

void LTESniffer_pcap_writer::close()
{
  fprintf(stdout, "Saving MAC PCAP file\n");
  DLT_PCAP_Close(pcap_file);
}

void LTESniffer_pcap_writer::set_ue_id(uint16_t ue_id) {
  this->ue_id = ue_id;
}

void LTESniffer_pcap_writer::pack_and_write(uint8_t* pdu, uint32_t pdu_len_bytes, uint32_t reTX, bool crc_ok, uint32_t tti, 
                              uint16_t crnti, uint8_t direction, uint8_t rnti_type)
{

  std::unique_lock<std::mutex> lock(pcap_mutex);
  if (enable_write) {
    MAC_Context_Info_t        context;
    context.direction       = direction;
    context.rntiType        = rnti_type;
    context.sysFrameNumber  = (uint16_t)(tti/10);
    context.subFrameNumber  = (uint16_t)(tti%10);
    context.rnti            = crnti;
    context.ueid            = (uint16_t)ue_id;
    context.isRetx          = (uint8_t)reTX;
    context.crcStatusOK     = crc_ok;
    context.radioType       = FDD_RADIO;
    context.isRetx          = reTX;
    context.nbiotMode       = 0;
    context.cc_idx          = 0;

    if (pdu) {
      LTE_PCAP_MAC_WritePDU(pcap_file, &context, pdu, pdu_len_bytes);
    }
  }
  lock.unlock();
}

void LTESniffer_pcap_writer::pack_and_write_api(uint8_t* pdu, uint32_t pdu_len_bytes, uint32_t reTX, bool crc_ok, uint32_t tti, 
                              uint16_t crnti, uint8_t direction, uint8_t rnti_type)
{

  std::unique_lock<std::mutex> lock(pcap_mutex);
  if (enable_write) {
    MAC_Context_Info_t        context;
    context.direction       = direction;
    context.rntiType        = rnti_type;
    context.sysFrameNumber  = (uint16_t)(tti/10);
    context.subFrameNumber  = (uint16_t)(tti%10);
    context.rnti            = crnti;
    context.ueid            = (uint16_t)ue_id;
    context.isRetx          = (uint8_t)reTX;
    context.crcStatusOK     = crc_ok;
    context.radioType       = FDD_RADIO;
    context.isRetx          = reTX;
    context.nbiotMode       = 0;
    context.cc_idx          = 0;

    if (pdu) {
      LTE_PCAP_MAC_WritePDU(pcap_file_api, &context, pdu, pdu_len_bytes);
    }
  }
  lock.unlock();
}

void LTESniffer_pcap_writer::write_dl_crnti(uint8_t* pdu, uint32_t pdu_len_bytes, uint16_t rnti, bool crc_ok, uint32_t tti, bool retx)
{
  pack_and_write(pdu, pdu_len_bytes, retx, crc_ok, tti, rnti, DIRECTION_DOWNLINK, C_RNTI);
}

void LTESniffer_pcap_writer::write_dl_ranti(uint8_t* pdu, uint32_t pdu_len_bytes, uint16_t rnti, bool crc_ok, uint32_t tti)
{
  pack_and_write(pdu, pdu_len_bytes, 0, crc_ok, tti, rnti, DIRECTION_DOWNLINK, RA_RNTI);
}

void LTESniffer_pcap_writer::write_dl_bch(uint8_t* pdu, uint32_t pdu_len_bytes, bool crc_ok, uint32_t tti)
{
  pack_and_write(pdu, pdu_len_bytes, 0, crc_ok, tti, 0, DIRECTION_DOWNLINK, NO_RNTI);
}

void LTESniffer_pcap_writer::write_dl_pch(uint8_t* pdu, uint32_t pdu_len_bytes, bool crc_ok, uint32_t tti)
{
  pack_and_write(pdu, pdu_len_bytes, 0, crc_ok, tti, SRSRAN_PRNTI, DIRECTION_DOWNLINK, P_RNTI);
}

void LTESniffer_pcap_writer::write_dl_sirnti(uint8_t* pdu, uint32_t pdu_len_bytes, bool crc_ok, uint32_t tti)
{
  pack_and_write(pdu, pdu_len_bytes, 0, crc_ok, tti, SRSRAN_SIRNTI, DIRECTION_DOWNLINK, SI_RNTI);
}

void LTESniffer_pcap_writer::write_ul_crnti(uint8_t* pdu, uint32_t pdu_len_bytes, uint16_t crnti, uint32_t tti)
{
  pack_and_write(pdu, pdu_len_bytes, 0, true, tti, crnti, DIRECTION_UPLINK, C_RNTI);
}

void LTESniffer_pcap_writer::write_ul_crnti_api(uint8_t* pdu, uint32_t pdu_len_bytes, uint16_t crnti, uint32_t tti)
{
  pack_and_write_api(pdu, pdu_len_bytes, 0, true, tti, crnti, DIRECTION_UPLINK, C_RNTI);
}

void LTESniffer_pcap_writer::write_dl_crnti_api(uint8_t* pdu, uint32_t pdu_len_bytes, uint16_t rnti, bool crc_ok, uint32_t tti, bool retx)
{
  pack_and_write_api(pdu, pdu_len_bytes, retx, crc_ok, tti, rnti, DIRECTION_DOWNLINK, C_RNTI);
}
