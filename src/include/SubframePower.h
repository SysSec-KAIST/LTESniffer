#pragma once

#include "falcon/phy/falcon_ue/falcon_ue_dl.h"
#include <vector>

class SubframePower {
public:
    SubframePower(const srsran_cell_t& cell);
    ~SubframePower();
    const std::vector<float>& getRBPowerDL() const {return rb_power_dl;}
    const std::vector<float>& getRBPowerUL() const {return rb_power_dl;}
    void computePower(const cf_t* sf_symbols);
    uint32_t getNofPRB() const { return nof_prb; }
    float getMax() const { return max; }
    float getMin() const { return min; }
private:
    uint32_t nof_prb;
    float max;
    float min;
    std::vector<float> rb_power_dl;
};
