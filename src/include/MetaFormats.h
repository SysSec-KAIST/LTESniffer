#pragma once

#include <stdint.h>

// include C-only headers
#ifdef __cplusplus
    extern "C" {
#endif

#include "srsran/phy/phch/dci.h"
#include "falcon/phy/falcon_phch/falcon_dci.h"
#ifdef __cplusplus
}
#undef I // Fix complex.h #define I nastiness when using C++
#endif

extern const srsran_dci_format_t falcon_ue_all_formats[];
extern const uint32_t nof_falcon_ue_all_formats;

class DCIMetaFormats {
public:
    DCIMetaFormats(uint32_t nformats, double split_ratio = 1.0);
    ~DCIMetaFormats();
    void setSplitRatio(double split_ratio);
    void update_formats();
    falcon_dci_meta_format_t** getPrimaryMetaFormats() const;
    falcon_dci_meta_format_t** getSecondaryMetaFormats() const;
    uint32_t getNofPrimaryMetaFormats() const;
    uint32_t getNofSecondaryMetaFormats() const;
    void setSkipSecondaryMetaFormats(bool skip);
    bool skipSecondaryMetaFormats() const;
    void printPrimaryMetaFormats() const;
    void printSecondaryMetaFormats() const;
private:
    falcon_dci_meta_format_t* all_meta_formats;
    falcon_dci_meta_format_t** primary_meta_formats;
    falcon_dci_meta_format_t** secondary_meta_formats;

    uint32_t nof_all_meta_formats;
    uint32_t nof_primary_meta_formats;
    uint32_t nof_secondary_meta_formats;
    bool skip_secondary_meta_formats;
    double split_ratio;
    void printMetaFormatList(falcon_dci_meta_format_t** formats, uint32_t nof_formats) const;
};
