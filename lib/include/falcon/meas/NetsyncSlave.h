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
#include "falcon/meas/BroadcastSlave.h"
#include "falcon/meas/AuxModem.h"
#include "falcon/meas/Cancelable.h"
#include "falcon/common/SignalManager.h"
#include <pthread.h>
#include <signal.h>
#include <condition_variable>

class NetsyncSlave : public NetsyncReceiverBase, public SignalHandler {
public:
  NetsyncSlave(const uint16_t port);
  ~NetsyncSlave();
  void pollReply();
  void startReply();
  void stopReply();
  void notifyFinished();
  void notifyError(const std::string text);

  void init(AuxModem* modem);
  bool waitStart();
  void signalStart();
  void signalAbort();
  bool stopReceived();
  void attachCancelable(Cancelable* obj);

  const NetsyncMessageStart& getRemoteParams() const;
protected:
  void handle(NetsyncMessagePoll msg);
  void handle(NetsyncMessageStart msg);
  void handle(NetsyncMessageStop msg);
private:
  void replyText(const std::string& text);
  void receive();
  void signal(bool abort);

  void handleSignal();
  BroadcastSlave broadcastSlave;
  AuxModem* modem;
  std::mutex startMutex;
  std::condition_variable startConditionVar;
  bool startFlag;
  bool stopFlag;
  Cancelable* stopObject;
  NetsyncMessageStart remoteParams;
  stringstream textstream;

  template<typename T>
  friend NetsyncSlave& operator<<(NetsyncSlave &s, const T &obj);
  friend NetsyncSlave& endl(NetsyncSlave& s);
  friend NetsyncSlave& operator<<(NetsyncSlave &s, NetsyncSlave& (*f)(NetsyncSlave&));
  //friend NetsyncSlave& operator<<(NetsyncSlave &s, std::ostream& (*f)(std::ostream&));
  //friend NetsyncSlave& operator<<(NetsyncSlave &s, std::ostream& (*f)(std::ios&));
  //friend NetsyncSlave& operator<<(NetsyncSlave &s, std::ostream& (*f)(std::ios_base&));
};

template<typename T>
NetsyncSlave& operator<<(NetsyncSlave &s, const T &obj) {
  std::cout << obj;
  s.textstream << obj;
  return s;
}

NetsyncSlave& endl(NetsyncSlave& s);
NetsyncSlave& operator<<(NetsyncSlave &s, NetsyncSlave& (*f)(NetsyncSlave&));
//NetsyncSlave& operator<<(NetsyncSlave &s, std::ostream& (*f)(std::ostream&));
//NetsyncSlave& operator<<(NetsyncSlave &s, std::ostream& (*f)(std::ios&));
//NetsyncSlave& operator<<(NetsyncSlave &s, std::ostream& (*f)(std::ios_base&));
