#include "include/DCIPrint.h"
#include "falcon/phy/common/falcon_phy_common.h"

#define ANSI_COLOR_RED     "\x1b[31m"
#define ANSI_COLOR_GREEN   "\x1b[32m"
#define ANSI_COLOR_YELLOW  "\x1b[33m"
#define ANSI_COLOR_BLUE    "\x1b[34m"
#define ANSI_COLOR_MAGENTA "\x1b[35m"
#define ANSI_COLOR_CYAN    "\x1b[36m"
#define ANSI_COLOR_RESET   "\x1b[0m"

const static char* color_rnti[] = {
  ANSI_COLOR_RED,
  ANSI_COLOR_GREEN,
  ANSI_COLOR_YELLOW,
  ANSI_COLOR_BLUE,
  ANSI_COLOR_MAGENTA,
  ANSI_COLOR_CYAN,
  ANSI_COLOR_GREEN,
  ANSI_COLOR_YELLOW,
  ANSI_COLOR_BLUE,
  ANSI_COLOR_MAGENTA
};

const static char* color_power[] = {
  ANSI_COLOR_BLUE,
  ANSI_COLOR_CYAN,
  ANSI_COLOR_GREEN,
  ANSI_COLOR_YELLOW,
  ANSI_COLOR_RED,
  ANSI_COLOR_MAGENTA,
  ANSI_COLOR_RESET,
  ANSI_COLOR_RESET
};

#define COLOR_RNTI(x) (color_rnti[x%10])
#define COLOR_POWER(x) (color_power[x%8])
#define COLOR_RESET ANSI_COLOR_RESET

void DCIPrint::printRBVectorColored(FILE* file, const std::vector<uint16_t>& map) {
  for(std::vector<uint16_t>::const_iterator it = map.begin(); it != map.end(); ++it) {
    if(*it == FALCON_UNSET_RNTI) {
      fprintf(file, COLOR_RESET "_");
    }
    else {
      fprintf(file, "%s", COLOR_RNTI(*it));
      fprintf(file, "%d", *it % 10);
    }
  }
  fprintf(file, COLOR_RESET);
}

void DCIPrint::printRBVector(FILE* file, const std::vector<uint16_t>& map) {
  for(std::vector<uint16_t>::const_iterator it = map.begin(); it != map.end(); ++it) {
    if(*it == FALCON_UNSET_RNTI) {
      fprintf(file, "_");
    }
    else {
      fprintf(file, "%d", *it % 10);
    }
  }
}

void DCIPrint::printPowerVectorColored(FILE* file, const std::vector<uint16_t>& map) {
  for(std::vector<uint16_t>::const_iterator it = map.begin(); it != map.end(); ++it) {
    if(*it == 0) {
      fprintf(file, COLOR_RESET "_");
    }
    else {
      fprintf(file, "%s", COLOR_POWER(*it));
      fprintf(file, "%d", *it % 8);
    }
  }
  fprintf(file, COLOR_RESET);
}
