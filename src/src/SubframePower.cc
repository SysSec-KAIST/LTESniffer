#include "include/SubframePower.h"
#include "srsran/phy/utils/vector.h"

#include <limits>
#include "include/Helper.h"

SubframePower::SubframePower(const srsran_cell_t& cell) :
  nof_prb(cell.nof_prb),
  rb_power_dl(cell.nof_prb, 0)
{

}

SubframePower::~SubframePower() {

}

void SubframePower::computePower(const cf_t *sf_symbols) {


#define SIMD_POWER
#ifdef SIMD_POWER
  //reset
  std::fill(rb_power_dl.begin(), rb_power_dl.end(), 0);

  //accumulate
  for (uint32_t j = 0; j < 14; j++) {
    for (uint32_t i = 0; i < nof_prb; i++) {
      rb_power_dl[i] += srsran_vec_avg_power_cf(&sf_symbols[i*12+j*(12*nof_prb)], 12);
    }
  }

  //log domain, division for average, max/min search
  max = -std::numeric_limits<float>::max();
  min = std::numeric_limits<float>::max();
  const float logDivBy = 10*(log10f(14));
  for (uint32_t i = 0; i< nof_prb; i++) {
      rb_power_dl[i] = 10 * log10f(rb_power_dl[i]) - logDivBy;
      max = rb_power_dl[i] > max ? rb_power_dl[i] : max;
      min = rb_power_dl[i] < min ? rb_power_dl[i] : min;
  }

#endif

//#define CLASSIC_POWER
#ifdef CLASSIC_POWER
  //reset
  std::fill(rb_power_dl.begin(), rb_power_dl.end(), 0);
  std::vector<float> tmp_plot_wf(12*nof_prb, 0);

  for (uint32_t j = 0; j < 14; j++) {
    for (uint32_t i = 0; i < 12*nof_prb; i++) {
      float tmp = my_cabsf(sf_symbols[i+j*(12*nof_prb)]);
      tmp_plot_wf[i] += tmp*tmp/14;
    }
  }

  float tmp_buff = 0;
  max = std::numeric_limits<float>::min();
  min = std::numeric_limits<float>::max();
  for(uint32_t i = 0; i < nof_prb; i++) {
    tmp_buff = 0;
    for(uint32_t ii = 0; ii < 12; ii++) {
      tmp_buff += tmp_plot_wf[(i*12)+ii]/12;
    }

    rb_power_dl[i] = 10 * log10f(tmp_buff);
    max = rb_power_dl[i] > max ? rb_power_dl[i] : max;
    min = rb_power_dl[i] < min ? rb_power_dl[i] : min;
  }

#endif

}

