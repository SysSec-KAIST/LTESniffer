#include "include/MetaFormats.h"

#include "srsran/phy/utils/debug.h"

#include <iostream>

DCIMetaFormats::DCIMetaFormats(uint32_t nformats, double split_ratio) {
  // Init formats
  nof_all_meta_formats = nformats;
  nof_primary_meta_formats = 0;
  nof_secondary_meta_formats = 0;
  skip_secondary_meta_formats = false;
  all_meta_formats = static_cast<falcon_dci_meta_format_t*>(calloc(nof_all_meta_formats, sizeof(falcon_dci_meta_format_t)));
  primary_meta_formats = static_cast<falcon_dci_meta_format_t**>(calloc(nof_all_meta_formats, sizeof(falcon_dci_meta_format_t*)));
  secondary_meta_formats = static_cast<falcon_dci_meta_format_t**>(calloc(nof_all_meta_formats, sizeof(falcon_dci_meta_format_t*)));
  for(uint32_t i=0; i<nof_all_meta_formats; i++) {
    all_meta_formats[i].format = falcon_ue_all_formats[i];
    all_meta_formats[i].global_index = i;
    all_meta_formats[i].hits = 0;
  }
  setSplitRatio(split_ratio);
  update_formats();  //100% of formats into primary category
}

DCIMetaFormats::~DCIMetaFormats() {
  nof_all_meta_formats = 0;
  nof_primary_meta_formats = 0;
  nof_secondary_meta_formats = 0;
  free(all_meta_formats);
  free(primary_meta_formats);
  free(secondary_meta_formats);
  all_meta_formats = nullptr;
  primary_meta_formats = nullptr;
  secondary_meta_formats = nullptr;
}

void DCIMetaFormats::setSplitRatio(double split_ratio) {
  this->split_ratio = split_ratio;
}

void DCIMetaFormats::update_formats() {
  falcon_dci_meta_format_t** sorted = static_cast<falcon_dci_meta_format_t**>(calloc(nof_all_meta_formats, sizeof(falcon_dci_meta_format_t*)));
  double total_hits = 0;
  // init and count
  for(uint32_t i=0; i<nof_all_meta_formats; i++) {
    sorted[i] = &all_meta_formats[i];
    total_hits += sorted[i]->hits;
  }

  falcon_dci_meta_format_t* dummy;
  // sort in descending order of hits
  for(int i=0; i<nof_all_meta_formats-1; i++) {
    int max_idx = i;
    for(int j=max_idx; j<nof_all_meta_formats; j++) {
      if(sorted[j]->hits > sorted[max_idx]->hits) {
        max_idx = j;
      }
    }
    dummy = sorted[i];
    sorted[i] = sorted[max_idx];
    sorted[max_idx] = dummy;
  }

  // prepare split
  double split_threshold = total_hits * split_ratio;
  double cumulation = 0;
  nof_primary_meta_formats = 0;
  nof_secondary_meta_formats = 0;

  // do the split
  for(int i=0; i<nof_all_meta_formats; i++) {
    if(cumulation <= split_threshold) {
      primary_meta_formats[nof_primary_meta_formats] = sorted[i];
      nof_primary_meta_formats++;
    }
    else {
      secondary_meta_formats[nof_secondary_meta_formats] = sorted[i];
      nof_secondary_meta_formats++;
    }
    cumulation += sorted[i]->hits;
    sorted[i]->hits = 0;  // reset hits;
  }
  free(sorted);

  if(SRSRAN_VERBOSE_ISINFO()) {
    printPrimaryMetaFormats();
    printSecondaryMetaFormats();
  }
}

falcon_dci_meta_format_t** DCIMetaFormats::getPrimaryMetaFormats() const {
  return primary_meta_formats;
}

falcon_dci_meta_format_t** DCIMetaFormats::getSecondaryMetaFormats() const {
  return secondary_meta_formats;
}

uint32_t DCIMetaFormats::getNofPrimaryMetaFormats() const {
  return nof_primary_meta_formats;
}

uint32_t DCIMetaFormats::getNofSecondaryMetaFormats() const {
  return nof_secondary_meta_formats;
}

void DCIMetaFormats::setSkipSecondaryMetaFormats(bool skip) {
  skip_secondary_meta_formats = skip;
}

bool DCIMetaFormats::skipSecondaryMetaFormats() const {
    return skip_secondary_meta_formats;
}

void DCIMetaFormats::printPrimaryMetaFormats() const {
    std::cout << "Primary DCI meta formats:" << std::endl;
    printMetaFormatList(primary_meta_formats, nof_primary_meta_formats);
}

void DCIMetaFormats::printSecondaryMetaFormats() const {
    std::cout << "Secondary DCI meta formats:" << std::endl;
    printMetaFormatList(secondary_meta_formats, nof_secondary_meta_formats);
}

void DCIMetaFormats::printMetaFormatList(falcon_dci_meta_format_t **formats, uint32_t nof_formats) const {
    for(uint32_t i=0; i< nof_formats; i++) {
        std::cout << srsran_dci_format_string(formats[i]->format) << std::endl;
    }
}
