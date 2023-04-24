#include "include/SubframeInfoConsumer.h"
#include "include/DCIPrint.h"



DCIConsumerList::~DCIConsumerList() {

}

void DCIConsumerList::consumeDCICollection(const SubframeInfo& subframeInfo) {
  for(auto& consumer : consumers) {
    consumer->consumeDCICollection(subframeInfo);
  }
}

void DCIConsumerList::addConsumer(std::shared_ptr<SubframeInfoConsumer> consumer)
{
  consumers.push_back(consumer);
}


DCIToFileBase::DCIToFileBase() :
  dci_file(stdout)
{

}

DCIToFileBase::DCIToFileBase(FILE* dci_file_) :
  dci_file(dci_file_)
{

}

DCIToFileBase::~DCIToFileBase() {

}

void DCIToFileBase::setFile(FILE* dci_file_) {
  this->dci_file = dci_file_;
}

FILE* DCIToFileBase::getFile() {
  return dci_file;
}

DCIToFile::DCIToFile() :
  DCIToFileBase()
{

}

DCIToFile::DCIToFile(FILE* dci_file_) :
  DCIToFileBase(dci_file_)
{

}

DCIToFile::~DCIToFile() {

}

void DCIToFile::consumeDCICollection(const SubframeInfo& collection) {
  printDCICollection(collection);
}

void DCIToFile::printDCICollection(const SubframeInfo& subframeInfo) const {
  const DCICollection& collection(subframeInfo.getDCICollection());
  struct timeval timestamp = collection.getTimestamp();

  // Downlink
  const std::vector<DCI_DL>& dci_dl = collection.getDCI_DL();
  for(std::vector<DCI_DL>::const_iterator dci = dci_dl.begin(); dci != dci_dl.end(); ++dci) {
    switch(dci->format) {
      case SRSRAN_DCI_FORMAT0:
        ERROR("Error: no reason to be here\n");
        break;
      case SRSRAN_DCI_FORMAT1:
      case SRSRAN_DCI_FORMAT1A:
      case SRSRAN_DCI_FORMAT1C:
      case SRSRAN_DCI_FORMAT1B:
      case SRSRAN_DCI_FORMAT1D:
        fprintf(dci_file,
                "%ld.%06ld\t%04d\t%d\t%d\t1\t"
                "%d\t%d\t%d\t%d\t%d\t"
                "%d\t%d\t%d\t%d\t"
                "%d\t%d\t%d\t%d\t%d\t%s\n",
                timestamp.tv_sec, timestamp.tv_usec, collection.get_sfn(), collection.get_sf_idx(), dci->rnti,
                dci->dl_grant->mcs[0].idx, dci->dl_grant->nof_prb, dci->dl_grant->mcs[0].tbs, -1, -1,
                dci->format+1, dci->dl_dci_unpacked->ndi, -1, dci->dl_dci_unpacked->harq_process,
                dci->location.ncce, dci->location.L, collection.get_cfi(), dci->histval, dci->nof_bits, dci->hex.c_str());
        break;
      case SRSRAN_DCI_FORMAT2:
      case SRSRAN_DCI_FORMAT2A:
      case SRSRAN_DCI_FORMAT2B:
        fprintf(dci_file,
                "%ld.%06ld\t%04d\t%d\t%d\t1\t"
                "%d\t%d\t%d\t%d\t%d\t"
                "%d\t%d\t%d\t%d\t"
                "%d\t%d\t%d\t%d\t%d\t%s\n",
                timestamp.tv_sec, timestamp.tv_usec, collection.get_sfn(), collection.get_sf_idx(), dci->rnti,
                dci->dl_grant->mcs[0].idx, dci->dl_grant->nof_prb, dci->dl_grant->mcs[0].tbs + dci->dl_grant->mcs[1].tbs, dci->dl_grant->mcs[0].tbs, dci->dl_grant->mcs[1].tbs,
                dci->format+1, dci->dl_dci_unpacked->ndi, dci->dl_dci_unpacked->ndi_1, dci->dl_dci_unpacked->harq_process,
                dci->location.ncce, dci->location.L, collection.get_cfi(), dci->histval, dci->nof_bits, dci->hex.c_str());
        break;
        //case SRSRAN_DCI_FORMAT3:
        //case SRSRAN_DCI_FORMAT3A:
      default:
        ERROR("Other formats\n");
    }
  }

  // Uplink
  const std::vector<DCI_UL>& dci_ul = collection.getDCI_UL();
  for(std::vector<DCI_UL>::const_iterator dci = dci_ul.begin(); dci != dci_ul.end(); ++dci) {
    if (dci->ul_dci_unpacked->mcs_idx < 29) {
      fprintf(dci_file,
              "%ld.%06ld\t%04d\t%d\t%d\t0\t"
              "%d\t%d\t%d\t%d\t%d\t"
              "0\t%d\t-1\t%d\t"
              "%d\t%d\t%d\t%d\t%d\t%s\n",
              timestamp.tv_sec, timestamp.tv_usec, collection.get_sfn(), collection.get_sf_idx(), dci->rnti,
              dci->ul_grant->mcs.idx, dci->ul_grant->L_prb, dci->ul_grant->mcs.tbs, -1, -1,
              dci->ul_dci_unpacked->ndi, (10*collection.get_sfn()+collection.get_sf_idx())%8,
              dci->location.ncce, dci->location.L, collection.get_cfi(), dci->histval, dci->nof_bits, dci->hex.c_str());
    }
    else {
      fprintf(dci_file,
              "%ld.%06ld\t%04d\t%d\t%d\t0\t"
              "%d\t%d\t%d\t%d\t%d\t"
              "0\t%d\t-1\t%d\t"
              "%d\t%d\t%d\t%d\t%d\t%s\n",
              timestamp.tv_sec, timestamp.tv_usec, collection.get_sfn(), collection.get_sf_idx(), dci->rnti,
              dci->ul_grant->mcs.idx, dci->ul_grant->L_prb, 0, -1, -1,
              dci->ul_dci_unpacked->ndi, (10*collection.get_sfn()+collection.get_sf_idx())%8,
              dci->location.ncce, dci->location.L, collection.get_cfi(), dci->histval, dci->nof_bits, dci->hex.c_str());
    }
  }
}

DCIDrawASCII::DCIDrawASCII() :
  DCIToFileBase()
{

}

DCIDrawASCII::DCIDrawASCII(FILE* dci_file_) :
  DCIToFileBase(dci_file_)
{

}

DCIDrawASCII::~DCIDrawASCII() {

}

void DCIDrawASCII::consumeDCICollection(const SubframeInfo& collection) {
  printRBMaps(collection);
}

void DCIDrawASCII::printRBMaps(const SubframeInfo& subframeInfo) const {
  const DCICollection& collection(subframeInfo.getDCICollection());
  fprintf(dci_file, "DL[");
  printRBVectorColored(collection.getRBMapDL());
  fprintf(dci_file, "] UL[");
  printRBVectorColored(collection.getRBMapUL());
  fprintf(dci_file, "]\n");
}

void DCIDrawASCII::printRBVector(const std::vector<uint16_t>& map) const {
  DCIPrint::printRBVector(dci_file, map);
}

void DCIDrawASCII::printRBVectorColored(const std::vector<uint16_t>& map) const {
  DCIPrint::printRBVectorColored(dci_file, map);
}

SubframeInfoConsumer::~SubframeInfoConsumer() {

}

PowerDrawASCII::PowerDrawASCII() :
  DCIToFileBase()
{

}

PowerDrawASCII::PowerDrawASCII(FILE* dci_file_) :
  DCIToFileBase(dci_file_)
{

}

PowerDrawASCII::~PowerDrawASCII() {

}

void PowerDrawASCII::consumeDCICollection(const SubframeInfo& subframeInfo) {
  const std::vector<float> power = subframeInfo.getSubframePower().getRBPowerDL();
  const float min = subframeInfo.getSubframePower().getMin();
  const float max = subframeInfo.getSubframePower().getMax();
  std::vector<uint16_t> repr(power.size());
  for(uint32_t prb=0; prb<power.size(); prb++) {
    repr[prb] = static_cast<uint16_t>(7 * (power[prb]-min) / (max-min));
  }
  fprintf(dci_file, "P [");
  printPowerVectorColored(repr);
  fprintf(dci_file, "]\n");
}

void PowerDrawASCII::printPowerVectorColored(const std::vector<uint16_t>& map) const {
  DCIPrint::printPowerVectorColored(dci_file, map);
}
