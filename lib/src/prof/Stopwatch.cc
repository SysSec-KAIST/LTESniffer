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
#include "falcon/prof/Stopwatch.h"
#include <cstdio>

Stopwatch::Stopwatch() {
  zero(timeStart);
}

void Stopwatch::start() {
  gettimeofday(&timeStart, nullptr);
}

timeval Stopwatch::getAndRestart() {
  timeval now;
  gettimeofday(&now, nullptr);
  timeval result = subtract(timeStart, now);
  timeStart = now;
  return result;
}

timeval Stopwatch::getAndContinue() const {
  timeval now;
  gettimeofday(&now, nullptr);
  timeval result = subtract(timeStart, now);
  return result;
}

std::string Stopwatch::toString(timeval t) {
  const size_t buf_sz = 20;
  char strbuf[buf_sz] = {0};
  snprintf(strbuf, buf_sz, "%ld.%06ld", t.tv_sec, t.tv_usec);
  strbuf[buf_sz-1] = 0; //prevent buffer overflows
  return std::string(strbuf);
}

void Stopwatch::zero(timeval& t) {
  t.tv_sec = 0;
  t.tv_usec = 0;
}

timeval Stopwatch::subtract(const timeval& subtrahend, const timeval& minuend) {
  timeval result;
  result.tv_sec = 0;
  result.tv_usec = 0;

  result.tv_sec = minuend.tv_sec - subtrahend.tv_sec;
  result.tv_usec = minuend.tv_usec - subtrahend.tv_usec;
  if (result.tv_usec < 0) {
    result.tv_sec--;
    result.tv_usec += 1000000;
  }
  if (result.tv_usec >= 1000000) {
    result.tv_sec++;
    result.tv_usec -= 1000000;
  }
  return result;
}

timeval operator-(const timeval& left, const timeval& right) {
  return Stopwatch::subtract(right, left);
}

bool operator==(const timeval& left, const timeval& right) {
  return left.tv_sec == right.tv_sec && left.tv_usec == right.tv_usec;
}

bool operator<(const timeval& left, const timeval& right) {
  // check equal
  if(left == right) return false;

  // check seconds
  if(left.tv_sec < right.tv_sec) {
    return true;
  }
  else if(left.tv_sec > right.tv_sec) {
    return false;
  }

  // check micro seconds
  if(left.tv_usec < right.tv_usec) {
    return true;
  }
  else if(left.tv_usec > right.tv_usec) {
    return false;
  }

  // this should never happen
  return false;
}
