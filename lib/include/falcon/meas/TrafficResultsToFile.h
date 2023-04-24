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

#include "TrafficGeneratorEventHandler.h"
#include "falcon/meas/TrafficGenerator.h"
#include "falcon/meas/NetsyncSlave.h"
#include <string>
#include <iostream>
#include <ostream>

class TrafficResultsToFile : public TrafficGeneratorEventHandler {
public:
  TrafficResultsToFile();
  TrafficResultsToFile(TrafficGenerator* trafficGenerator);
  TrafficResultsToFile(TrafficGenerator* trafficGenerator,
                       const std::string &outputFileName);
  virtual ~TrafficResultsToFile() override {}

  void setTrafficGenerator(TrafficGenerator* trafficGenerator);
  void setOutputFileName(const std::string &outputFileName);
  void setDelimiter(const std::string &delimiter);

  /* base class interface */
  void actionBeforeTransfer() override;
  void actionDuringTransfer() override;
  void actionAfterTransfer() override;

protected:
  TrafficGenerator* trafficGenerator;
private:
  std::string outputFileName;
  std::string delimiter;

  void saveResults();
};

class TrafficResultsToFileAndNetsyncMessages : public TrafficResultsToFile {
public:
  TrafficResultsToFileAndNetsyncMessages(TrafficGenerator* trafficGenerator,
                                         const std::string &outputFileName,
                                         NetsyncSlave* netsync);

  /* base class interface */
  void actionAfterTransfer() override;
private:
  NetsyncSlave* netsync;
};

class TrafficResultsToFileAndNetsyncMessagesStopTxPowerSampling : public TrafficResultsToFileAndNetsyncMessages {
public:
  TrafficResultsToFileAndNetsyncMessagesStopTxPowerSampling(TrafficGenerator* trafficGenerator,
                                         const std::string &outputFileName,
                                         NetsyncSlave* netsync,
                                         AuxModem* modem);

  /* base class interface */
  void actionAfterTransfer() override;
private:
  AuxModem* modem;
};
