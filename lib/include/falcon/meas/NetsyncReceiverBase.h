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

#include "NetsyncCommon.h"
#include <pthread.h>
#include <signal.h>

class NetsyncReceiverBase {
public:
  NetsyncReceiverBase();
  virtual ~NetsyncReceiverBase();
  void parse(const char* msg, size_t len);
  void launchReceiver();
protected:
  virtual void handle(NetsyncMessageStart msg);
  virtual void handle(NetsyncMessageStop msg);
  virtual void handle(NetsyncMessagePoll msg);
  virtual void handle(NetsyncMessageText msg);
private:
  virtual void receive() = 0;
  static void* receiveStart(void* obj);

  pthread_t recvThread;

protected:
  char* recvThreadBuf;
  size_t recvThreadBufSize;
  volatile bool cancelThread;
};
