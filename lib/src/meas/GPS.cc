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
#include "falcon/meas/GPS.h"

#include <sstream>

using namespace std;

GPS::GPS() {

}

GPS::~GPS() {

}

string GPS::toCSV(const GPSFix& obj, const string& delim) {
  stringstream stream;
  stream << obj.latitude << delim;
  stream << obj.longitude;
  // maybe other members, too

  return stream.str();
}


DummyGPS::DummyGPS() {

}

DummyGPS::~DummyGPS() {

}

GPSFix DummyGPS::getFix() {
  GPSFix result;
  result.is_invalid = true;
  return result;
}
