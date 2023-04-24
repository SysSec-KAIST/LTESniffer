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

#include <iostream>
#include <sstream>
#include <string>
#include <memory>
#include <pthread.h>
#include <signal.h>

#include "falcon/meas/NetsyncMaster.h"

class NetsyncController {
public:
  NetsyncController();
  ~NetsyncController();
  void init(std::shared_ptr<NetsyncMaster> netsyncMaster,
            uint32_t defaultPollIntervalSec,
            uint32_t defaultAutoIntervalSec);
  bool parse(std::istream& params);
private:
  void showHelp();
  void unknownToken(const std::string token);
  void parsePoll(std::istream& params);
  void parseAuto(std::istream &params);
  void parseStart(std::istream& params);
  static void* pollStart(void* obj);
  static void* autoStart(void* obj);
  void pollFunc();
  void autoFunc();
  string getTimestampString();

  std::shared_ptr<NetsyncMaster> netsyncMaster;
  uint32_t defaultPollIntervalSec;
  uint32_t defaultAutoIntervalSec;
  uint32_t autoIntervalSec;
  pthread_t pollThread;
  pthread_t autoThread;
  volatile bool cancelPollThread;
  volatile bool cancelAutoThread;
  volatile bool pollThreadActive;
  volatile bool autoThreadActive;
};
