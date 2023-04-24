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
#include "falcon/prof/Lifetime.h"

#include <iostream>

using namespace std;

Lifetime::Lifetime(LifetimeCollector& collector, const string& prefixText) :
  collector(collector),
  prefixText(prefixText)
{
  stopwatch.start();
}

Lifetime::~Lifetime() {
  collector.collect(*this);
}

timeval Lifetime::getLifetime() {
  return stopwatch.getAndContinue();
}

string Lifetime::getLifetimeString() {
  return Stopwatch::toString(getLifetime());
}

const string& Lifetime::getPrefixText() const {
  return prefixText;
}

void Lifetime::setPrefixText(const string& prefixText) {
  this->prefixText = prefixText;
}

LifetimeCollector::~LifetimeCollector() {
  //nothing
}

GlobalLifetimePrinter* GlobalLifetimePrinter::instance = nullptr;
GlobalLifetimePrinter& GlobalLifetimePrinter::getInstance() {
  if(instance == nullptr) {
    instance = new GlobalLifetimePrinter();
  }
  return *instance;
}

void GlobalLifetimePrinter::collect(Lifetime& lt) {
  cout << lt.getPrefixText() << lt.getLifetimeString() << endl;
}

GlobalLifetimePrinter::GlobalLifetimePrinter() {
  //nothing
}

PrintLifetime::PrintLifetime(const string& prefixText) :
  Lifetime(GlobalLifetimePrinter::getInstance(), prefixText)
{
  //nothing
}

PrintLifetime::~PrintLifetime() {
  //work is done by virtual base-class destructor
}
