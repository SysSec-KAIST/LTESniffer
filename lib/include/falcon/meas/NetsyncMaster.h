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

#include "falcon/meas/NetsyncCommon.h"
#include "falcon/meas/NetsyncReceiverBase.h"
#include "falcon/meas/BroadcastMaster.h"

#include "falcon/meas/GPS.h"


class NetsyncMaster : public NetsyncReceiverBase {
public:
  NetsyncMaster(const string& ip, const uint16_t port);
  ~NetsyncMaster();
  void init(uint32_t nofSubframes,
            uint32_t offsetSubframes,
            size_t payloadSize,
            const string& urlUL,
            const string& urlDL,
            GPS* gps,
            uint32_t txPowerSamplingInterval);
  void start(const string& id, uint32_t direction);
  void stop();
  void poll();
  void location();
protected:
  void handle(NetsyncMessageText msg);
private:
  void receive();
  BroadcastMaster broadcastMaster;
  uint32_t nofSubframes;
  uint32_t offsetSubframes;
  size_t payloadSize;
  string urlUL;
  string urlDL;
  GPS* gps;
  uint32_t txPowerSamplingInterval;
};
