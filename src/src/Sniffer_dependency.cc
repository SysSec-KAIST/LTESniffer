#include "include/Sniffer_dependency.h"

DCI_BASE::DCI_BASE() :
  rnti(FALCON_UNSET_RNTI),
  format(SRSRAN_DCI_NOF_FORMATS),
  nof_bits(0),
  hex(),
  location({0, 0}),
  histval(0)
{

}

DCI_DL::DCI_DL() :
  DCI_BASE(),
  dl_dci_unpacked(new srsran_ra_dl_dci_t),
  dl_grant(new srsran_ra_dl_grant_t)
{

}

DCI_UL::DCI_UL() :
  DCI_BASE(),
  ul_dci_unpacked(new srsran_ra_ul_dci_t),
  ul_grant(new srsran_ra_ul_grant_t),
  ran_ul_dci(new srsran_dci_ul_t),
  ran_ul_grant(new srsran_pusch_grant_t),
  ran_ul_grant_256(new srsran_pusch_grant_t)
{

}

DL_Sniffer_DCI_DL::DL_Sniffer_DCI_DL():
  DCI_BASE(),
  ran_dci_dl(new srsran_dci_dl_t),
  ran_pdsch_grant(new srsran_pdsch_grant_t),
  ran_pdsch_grant_256(new srsran_pdsch_grant_t)
{

}
