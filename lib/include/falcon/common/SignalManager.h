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

#include <vector>

class SignalGate;

class SignalHandler {
public:
  SignalHandler();
  SignalHandler(const SignalHandler&) = delete; //prevent copy
  SignalHandler& operator=(const SignalHandler&) = delete; //prevent copy
  virtual ~SignalHandler();
private:
  friend class SignalGate;
  virtual void handleSignal() = 0;
  void registerGate(SignalGate& gate);
  void deregisterGate();
  SignalGate* gate;
};

class SignalGate {
public:
  static SignalGate& getInstance();
  static void signalEntry(int sigNo);
  virtual ~SignalGate();
  void init();
  void attach(SignalHandler& handler);
  void detach(SignalHandler& handler);
private:
  SignalGate();
  SignalGate(const SignalGate&) = delete; //prevent copy
  SignalGate& operator=(const SignalGate&) = delete; //prevent copy
  void notify();
  static SignalGate* instance;
  std::vector<SignalHandler*> handlers;
};
