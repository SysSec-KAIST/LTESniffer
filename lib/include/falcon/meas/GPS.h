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

#include <string>

struct GPSFix {
  double latitude;        // canonical representation, e.g. 51.2849584
  double longitude;       // canonical representation, e.g. -4.6948374
  // missing time
//  float loc_unc_angle;    // degree
//  float loc_unc_a;        // meter
//  float loc_unc_p;        // meter
//  float hepe;             // meter
  int altitude;           // meter
//  float loc_unc_ve;       // meter
  float heading;          // degree
  float velocity_h;       // meter/sec
  float velocity_v;       // meter/sec
  int is_invalid;         // if "Not Available" found in response
  GPSFix() :
    latitude(0.0),
    longitude(0.0),
    altitude(0),
    heading(0.0),
    velocity_h(0.0),
    is_invalid(true)
  {}
};

class GPS {
public:
  GPS();
  GPS(const GPS&) = delete; //prevent copy
  GPS& operator=(const GPS&) = delete; //prevent copy
  virtual ~GPS();
  virtual GPSFix getFix() = 0;
  static std::string toCSV(const GPSFix& obj, const std::string& delim);
};

class DummyGPS : public GPS {
public:
  DummyGPS();
  DummyGPS(const DummyGPS&) = delete; //prevent copy
  DummyGPS& operator=(const DummyGPS&) = delete; //prevent copy
  ~DummyGPS() override;
  virtual GPSFix getFix() override;
};
