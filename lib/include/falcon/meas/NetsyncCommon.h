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

#include <cstddef>
#include <string>
#include <iostream>
#include <sstream>

using namespace std;

enum NetsyncMessageIdentifier {
  NMIStart = 0,
  NMIStop,
  NMIPoll,
  NMIText
};


class NetsyncMessageStart {
private:
  string id;
  uint32_t nofSubframes;
  uint32_t offsetSubframes;
  uint32_t direction;
  size_t payloadSize;
  string url;
  double latitude;
  double longitude;
  uint32_t txPowerSamplingInterval;

public:
  NetsyncMessageStart(const char* firstByte, size_t length) {
    string seq(firstByte, 0, length);
    istringstream istr(seq);
    istr >> id;
    istr >> nofSubframes;
    istr >> offsetSubframes;
    istr >> direction;
    istr >> payloadSize;
    istr >> url;
    istr >> latitude;
    istr >> longitude;
    istr >> txPowerSamplingInterval;
  }
  NetsyncMessageStart() :
    id(),
    nofSubframes(0),
    offsetSubframes(0),
    direction(0),
    url(),
    latitude(0),
    longitude(0),
    txPowerSamplingInterval(0)
  {}
  friend ostream& operator<<(ostream& os, const NetsyncMessageStart& obj) {
    NetsyncMessageIdentifier id = NMIStart;
    os.write(reinterpret_cast<const char*>(&id), sizeof(id));
    os << obj.id << " ";
    os << obj.nofSubframes << " ";
    os << obj.offsetSubframes << " ";
    os << obj.direction << " ";
    os << obj.payloadSize << " ";
    os << obj.url << " ";
    os << obj.latitude << " ";
    os << obj.longitude << " ";
    os << obj.txPowerSamplingInterval;
    os << '\0';
    return os;
  }

  uint32_t getNofSubframes() const {
    return nofSubframes;
  }

  void setNofSubframes(const uint32_t& value) {
    nofSubframes = value;
  }

  uint32_t getOffsetSubframes() const {
    return offsetSubframes;
  }

  void setOffsetSubframes(const uint32_t& value) {
    offsetSubframes = value;
  }

  uint32_t getDirection() const {
    return direction;
  }

  void setDirection(const uint32_t& value) {
    direction = value;
  }

  size_t getPayloadSize() const {
    return payloadSize;
  }

  void setPayloadSize(const size_t& value) {
    payloadSize = value;
  }

  string getUrl() const {
    return url;
  }

  void setUrl(const string& value) {
    url = value;
  }

  string getId() const {
    return id;
  }

  void setId(const string& value) {
    id = value;
  }

  double getLongitude() const {
    return longitude;
  }

  void setLongitude(double value) {
    longitude = value;
  }

  double getLatitude() const {
    return latitude;
  }

  void setLatitude(double value) {
    latitude = value;
  }

  uint32_t getTxPowerSamplingInterval() const {
    return  txPowerSamplingInterval;
  }

  void setTxPowerSamplingInterval(const uint32_t& value) {
    txPowerSamplingInterval = value;
  }
};

class NetsyncMessageStop {
public:
  NetsyncMessageStop(const char* firstByte, size_t length) {}
  NetsyncMessageStop() {}
  friend ostream& operator<<(ostream& os, const NetsyncMessageStop& obj) {
    NetsyncMessageIdentifier id = NMIStop;
    os.write(reinterpret_cast<const char*>(&id), sizeof(id));
    return os;
  }
};

class NetsyncMessagePoll {
public:
  NetsyncMessagePoll(const char* firstByte, size_t length) {}
  NetsyncMessagePoll() {}
  friend ostream& operator<<(ostream& os, const NetsyncMessagePoll& obj) {
    NetsyncMessageIdentifier id = NMIPoll;
    os.write(reinterpret_cast<const char*>(&id), sizeof(id));
    return os;
  }
};

class NetsyncMessageText {

private:
  string text;
public:
  NetsyncMessageText(const char* firstByte, size_t length) :
    text(firstByte, length)
  {}
  NetsyncMessageText() : text() {}
  friend ostream& operator<<(ostream& os, const NetsyncMessageText& obj) {
    NetsyncMessageIdentifier id = NMIText;
    os.write(reinterpret_cast<const char*>(&id), sizeof(id));
    os << obj.text;
    os << '\0';
    return os;
  }
  void setText(string text) {
    this->text = text;
  }
  string getText() const { return text; }
};

struct __attribute__((__packed__)) RawMessage {
  NetsyncMessageIdentifier type;
  const char firstPayloadByte;
};
