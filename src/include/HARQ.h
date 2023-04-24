#pragma once

#include <mutex>
#include <time.h>
#include <memory>
#include <vector>
#include <string.h>
#include "shared_mutex"
#include "falcon/phy/falcon_ue/falcon_ue_dl.h"
#include  "Sniffer_dependency.h"

using namespace std;
// include C-only headers
#ifdef __cplusplus
	extern "C" {
#endif

#include "srsran/phy/phch/dci.h"

#ifdef __cplusplus
}
#undef I // Fix complex.h #define I nastiness when using C++
#endif

#ifdef __cplusplus
    extern "C" {
#endif

#include "srsran/phy/fec/softbuffer.h"
#include "srsran/phy/common/phy_common.h"
#include "srsran/phy/phch/phich.h"
// #include "srsran/phy/phch/pdsch.h"
// #include "srsran/phy/phch/ra.h"
// #include "srsran/phy/ue/ue_dl.h"

#ifdef __cplusplus
}
#endif

#define DL_SNIFFER_NEW_TX 0
#define DL_SNIFFER_RE_TX 1
#define DL_SNIFFER_HARQ_FULL_BUFFER 2
#define DL_SNIFFER_DECODED 3
#define DL_SNIFFER_HARQ_BUSY 4
#define DL_SNIFFER_MAX_HARQ_PROCESS 8
#define DL_SNIFFER_MAX_HARQ_SIZE 150
#define DL_SNIFFER_HARQ_MODE_OFF 0
#define DL_SNIFFER_HARQ_MODE_ON 1
#define DL_SNIFFER_HARQ_MODE_NO_BUFFER 2

struct dl_sniffer_harq_grant_t{
    bool last_decoded = false;
    bool ndi = false;
    bool ndi_present = false;
    int  rv = 0;
    int tbs = 0;
    bool is_first_transmission = true;
};

struct dl_sniffer_harq_tb_t {
    dl_sniffer_harq_tb_t();
    ~dl_sniffer_harq_tb_t();
    uint32_t sfn = 0;
    uint32_t sf_idx = 0;
    std::mutex using_mutex;
    dl_sniffer_harq_grant_t grant; //last grant;
    srsran_softbuffer_rx_t *buffer;
};


struct dl_sniffer_harq_process_t {
    int pid; //process id;
    uint32_t nof_retx = 0;
    dl_sniffer_harq_tb_t tb[SRSRAN_MAX_CODEWORDS];
    };

struct dl_sniffer_harq_entity_t{
    uint16_t rnti = 0;
    clock_t time = 0;
    uint32_t nof_active = 0;
    uint32_t nof_success = 0;
    uint32_t nof_retx_success = 0;
    dl_sniffer_harq_process_t harq_process[DL_SNIFFER_MAX_HARQ_PROCESS];
};


class HARQ
{
public:
    HARQ(/* args */);
    ~HARQ();
    void init_HARQ(int harq_mode_);
    int  is_retransmission(uint16_t RNTI, 
                          int pid,
                          int tid, 
                          dl_sniffer_harq_grant_t grant,
                          uint32_t sfn,
                          uint32_t sf_idx);

    // void addRNTI(uint16_t RNTI, 
    //              int pid, 
    //              int tid, 
    //              dl_sniffer_harq_grant_t grant,
    //              uint32_t sfn,
    //              uint32_t sf_idx);

    srsran_softbuffer_rx_t* getHARQBuffer(uint16_t RNTI, 
                                           int pid, 
                                           int tid);

    void updateHARQRNTI(uint16_t RNTI, 
                          int pid,
                          int tid,
                          uint32_t sfn,
                          uint32_t sf_idx,
                          dl_sniffer_harq_grant_t cur_grant);
    void updateStatisticRNTI(uint16_t RNTI, 
                             int pid,
                             bool is_retx,
                             bool success);
    void updateHARQDatabase();
    void updateProcess(int pid,
                       int tid,
                       uint32_t sfn,
                       uint32_t sf_idx,
                       dl_sniffer_harq_grant_t cur_grant,
                       dl_sniffer_harq_entity_t *harq_entity);
    int  harqBufferSize(){ return harq_database.size();}
    bool comparetti(uint32_t last_tti, uint32_t cur_tti);
    void printHARQDatabase();

    int getlastTbs(uint16_t RNTI, int pid, int tid);

private:
    int harq_mode = 0;
    int max_size = DL_SNIFFER_MAX_HARQ_SIZE;
    int nof_aval = DL_SNIFFER_MAX_HARQ_SIZE;
    long double interval = 5.0;
    std::mutex harq_mutex;
    std::vector<std::shared_ptr<dl_sniffer_harq_entity_t>> harq_database;
};

//check last_decoded

/*----------------- UL HARQ implementation------------------*/

struct ul_sniffer_harq_t{
    uint16_t tti = 0;
    uint16_t rnti = 0;
    clock_t time = 0;
    DCI_UL last_dci_ul;
    srsran_phich_grant_t phich_grant = {};
    int decode_result = 0;
};

class UL_HARQ
{
public:
    UL_HARQ(/* args */);
    ~UL_HARQ();
    int  is_retransmission(uint16_t RNTI, 
                          int pid,
                          int tid, 
                          dl_sniffer_harq_grant_t grant,
                          uint32_t sfn,
                          uint32_t sf_idx);

    void updateHARQRNTI(uint16_t RNTI, 
                        uint32_t sfn,
                        uint32_t sf_idx,
                        int decode_result,
                        DCI_UL cur_dci_ul);

    void updateStatisticRNTI(uint16_t RNTI, 
                             int pid,
                             bool is_retx,
                             bool success);
    void updateHARQDatabase();
    void updateProcess(int pid,
                       int tid,
                       uint32_t sfn,
                       uint32_t sf_idx,
                       dl_sniffer_harq_grant_t cur_grant,
                       dl_sniffer_harq_entity_t *harq_entity);

    bool comparetti(uint32_t last_tti, uint32_t cur_tti);
    void printHARQDatabase();

    std::vector<std::shared_ptr<ul_sniffer_harq_t>> get_database()
    {
        return ul_harq_database;
    }


private:
    int max_size = DL_SNIFFER_MAX_HARQ_SIZE;
    int nof_aval = DL_SNIFFER_MAX_HARQ_SIZE;
    long double interval = 10.0;
    std::mutex ul_harq_mutex;
    std::vector<std::shared_ptr<ul_sniffer_harq_t>> ul_harq_database;
};