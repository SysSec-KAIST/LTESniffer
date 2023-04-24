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
#include "falcon/meas/BroadcastMaster.h"

BroadcastMaster::BroadcastMaster(const string& ip, const uint16_t port) :
  bmHandle(nullptr)
{
  bmHandle = broadcast_master_init(ip.c_str(), port);
}

BroadcastMaster::~BroadcastMaster() {
  broadcast_master_destroy(bmHandle);
}

bool BroadcastMaster::sendBytes(const char *buf, size_t length) {
  return broadcast_master_send(bmHandle, buf, length) == 0;
}

size_t BroadcastMaster::receiveBytes(char *buf, size_t bufSize) {
  return broadcast_master_receive(bmHandle, buf, bufSize);
}
