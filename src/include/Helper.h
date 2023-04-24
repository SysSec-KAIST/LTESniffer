#pragma once

#ifdef __cplusplus
    extern "C" {
#endif

#include <complex.h>
#include <math.h>
#include "srsran/config.h"

float my_cabsf(cf_t c);

#ifdef __cplusplus
}
#undef I // Fix complex.h #define I nastiness when using C++
#endif
