#pragma once

#include <stdint.h>
#include <stdio.h>
#include <vector>

class DCIPrint {
public:
    static void printRBVectorColored(FILE* file, const std::vector<uint16_t>& map);
    static void printRBVector(FILE* file, const std::vector<uint16_t>& map);
    static void printPowerVectorColored(FILE* file, const std::vector<uint16_t>& map);
};
