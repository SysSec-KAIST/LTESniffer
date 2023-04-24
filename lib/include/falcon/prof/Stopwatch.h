/*
 * Copyright (c) 2019 Robert Falkenberg.
 *
 * This file is part of FALCON 
 * (see https://github.com/falkenber9/falcon).
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * A copy of the GNU Affero General Public License can be found in
 * the LICENSE file in the top-level directory of this distribution
 * and at http://www.gnu.org/licenses/.
 */
#pragma once

#include <time.h>
#include <sys/time.h>
#include <string>

class Stopwatch {
public:
  Stopwatch();
  Stopwatch(const Stopwatch&) = delete;
  Stopwatch& operator=(const Stopwatch&) = delete;
  ~Stopwatch() {}
  void start();
  timeval getAndRestart();
  timeval getAndContinue() const;
  static std::string toString(timeval t);
  static timeval subtract(const timeval& subtrahend, const timeval& minuend);
private:
  timeval timeStart;
  static void zero(timeval& t);
};

timeval operator-(const timeval& left, const timeval& right);
bool operator==(const timeval& left, const timeval& right);
bool operator<(const timeval& left, const timeval& right);
