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

#include "Stopwatch.h"

class Lifetime;

class LifetimeCollector {
public:
  virtual void collect(Lifetime& lt) = 0;
  virtual ~LifetimeCollector();
};

class Lifetime {
public:
  Lifetime(LifetimeCollector& collector, const std::string& prefixText = "");
  Lifetime(const Lifetime&) = delete;
  Lifetime& operator=(const Lifetime&) = delete;
  virtual ~Lifetime();
  timeval getLifetime();
  std::string getLifetimeString();
  const std::string& getPrefixText() const;
  void setPrefixText(const std::string& prefixText);
private:
  LifetimeCollector& collector;
  Stopwatch stopwatch;
  std::string prefixText;
};

class PrintLifetime : public Lifetime {
public:
  PrintLifetime(const std::string& prefixText = "");
  PrintLifetime(const PrintLifetime&) = delete;
  PrintLifetime& operator=(const PrintLifetime&) = delete;
  ~PrintLifetime() override;
};

class GlobalLifetimePrinter : public LifetimeCollector {
public:
  static GlobalLifetimePrinter& getInstance();
  void collect(Lifetime& lt) override;
private:
  GlobalLifetimePrinter();
  static GlobalLifetimePrinter* instance;
};
