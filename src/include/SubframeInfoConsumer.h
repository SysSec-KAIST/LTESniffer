#pragma once

#include "SubframeInfo.h"

class SubframeInfoConsumer {

public:
  virtual ~SubframeInfoConsumer();
  virtual void consumeDCICollection(const SubframeInfo& collection) = 0;
};

class DCIConsumerList : public SubframeInfoConsumer {
public:
  virtual ~DCIConsumerList() override;
  virtual void consumeDCICollection(const SubframeInfo &collection) override;
  void addConsumer(std::shared_ptr<SubframeInfoConsumer> consumer);
private:
  std::vector<std::shared_ptr<SubframeInfoConsumer>> consumers;
};

class DCIToFileBase : public SubframeInfoConsumer {
public:
  DCIToFileBase();
  DCIToFileBase(FILE* dci_file);
  virtual ~DCIToFileBase() override;
  void setFile(FILE* dci_file);
  FILE* getFile();
  virtual void consumeDCICollection(const SubframeInfo& subframeInfo) override = 0;
protected:
  FILE* dci_file;
};

class DCIToFile : public DCIToFileBase {
public:
    DCIToFile();
    DCIToFile(FILE* dci_file);
    virtual ~DCIToFile() override;
    virtual void consumeDCICollection(const SubframeInfo& subframeInfo) override;
private:
    void printDCICollection(const SubframeInfo& collection) const;
};

class DCIDrawASCII : public DCIToFileBase {
public:
  DCIDrawASCII();
  DCIDrawASCII(FILE* dci_file);
  virtual ~DCIDrawASCII() override;
  virtual void consumeDCICollection(const SubframeInfo& subframeInfo) override;
private:
  void printRBMaps(const SubframeInfo& subframeInfo) const;
  void printRBVector(const std::vector<uint16_t>& map) const;
  void printRBVectorColored(const std::vector<uint16_t>& map) const;
};

class PowerDrawASCII : public DCIToFileBase {
public:
  PowerDrawASCII();
  PowerDrawASCII(FILE* dci_file);
  virtual ~PowerDrawASCII() override;
  virtual void consumeDCICollection(const SubframeInfo &subframeInfo) override;
private:
  void printPowerVectorColored(const std::vector<uint16_t>& map) const;
};
