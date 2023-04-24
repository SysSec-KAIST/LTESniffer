#include "include/HARQ.h"


dl_sniffer_harq_tb_t::dl_sniffer_harq_tb_t():
buffer()
{
    buffer = new srsran_softbuffer_rx_t;
}

dl_sniffer_harq_tb_t::~dl_sniffer_harq_tb_t()
{

}

HARQ::HARQ(/* args */)
{
    for (int i = 0; i < max_size; i++){
        harq_database.push_back(std::shared_ptr<dl_sniffer_harq_entity_t>(new dl_sniffer_harq_entity_t));
    }
    // std::vector<std::shared_ptr<dl_sniffer_harq_entity_t>>::iterator iter;
    // for (iter = harq_database.begin(); iter != harq_database.end(); iter++){
    //     for (int i = 0; i < DL_SNIFFER_MAX_HARQ_PROCESS; i++){
    //         for (int j = 0; j < SRSRAN_MAX_CODEWORDS; j++){
    //             srsran_softbuffer_rx_init((*iter)->harq_process[i].tb[j].buffer, SRSRAN_MAX_PRB);
    //         }
    //     }
    // }
}

HARQ::~HARQ()
{
    if (harq_mode){
        std::vector<std::shared_ptr<dl_sniffer_harq_entity_t>>::iterator iter;
        for (iter = harq_database.begin(); iter != harq_database.end(); iter++){
            for (int i = 0; i < DL_SNIFFER_MAX_HARQ_PROCESS; i++){
                for (int j = 0; j < SRSRAN_MAX_CODEWORDS; j++){
                    srsran_softbuffer_rx_free((*iter)->harq_process[i].tb[j].buffer);
                }
            }
        }
    }
}

void HARQ::init_HARQ(int harq_mode_){
    harq_mode = harq_mode_;
    if (harq_mode){
        for (int i = 0; i < max_size; i++){
            harq_database.push_back(std::shared_ptr<dl_sniffer_harq_entity_t>(new dl_sniffer_harq_entity_t));
        }
        std::vector<std::shared_ptr<dl_sniffer_harq_entity_t>>::iterator iter;
        for (iter = harq_database.begin(); iter != harq_database.end(); iter++){
            for (int i = 0; i < DL_SNIFFER_MAX_HARQ_PROCESS; i++){
                for (int j = 0; j < SRSRAN_MAX_CODEWORDS; j++){
                    srsran_softbuffer_rx_init((*iter)->harq_process[i].tb[j].buffer, SRSRAN_MAX_PRB);
                }
            }
        }
    }
}
bool HARQ::comparetti(uint32_t last_tti, uint32_t cur_tti){
    uint32_t cp1 = cur_tti - last_tti;
    uint32_t cp2 = cur_tti + 10240 - last_tti;
    if (cp1 == 8 || cp2 == 8){
        return true;
    } else {
        return false;
    }
}


int HARQ::is_retransmission(uint16_t RNTI, 
                            int pid,
                            int tid, 
                            dl_sniffer_harq_grant_t cur_grant,
                            uint32_t sfn,
                            uint32_t sf_idx)
{
    std::unique_lock<std::mutex> harq_lock(harq_mutex);
    std::shared_ptr<dl_sniffer_harq_entity_t> harq_entity = nullptr;
    std::shared_ptr<dl_sniffer_harq_entity_t> avai_harq_entity = nullptr;
    bool found = false;
    std::vector<std::shared_ptr<dl_sniffer_harq_entity_t>>::iterator iter;
    for (iter = harq_database.begin(); iter != harq_database.end(); iter++){
        if ((*iter)->rnti == RNTI){
            harq_entity = *iter;
            found = true;
        }else if ((*iter)->rnti == 0){
            avai_harq_entity = *iter;
        }
    }
    if (found == false && avai_harq_entity != nullptr){
        avai_harq_entity->rnti = RNTI;
        avai_harq_entity->harq_process[pid].tb[tid].using_mutex.lock();
        (nof_aval>0)?(nof_aval--):(nof_aval);
        return DL_SNIFFER_NEW_TX;
    } else if (found == false && avai_harq_entity == nullptr){
        return DL_SNIFFER_HARQ_FULL_BUFFER;
    } else {
        clock_t cur_time = clock();
        uint32_t last_tti = harq_entity->harq_process[pid].tb[tid].sfn*10 + harq_entity->harq_process[pid].tb[tid].sf_idx;
        uint32_t cur_tti  = sfn*10 + sf_idx;\
        bool locked = false;
        if (!comparetti(last_tti, cur_tti)){
            locked = harq_entity->harq_process[pid].tb[tid].using_mutex.try_lock();
            if (locked) {return DL_SNIFFER_NEW_TX;}
            else {
                return DL_SNIFFER_HARQ_BUSY;
            }
        } else {
            dl_sniffer_harq_grant_t last_grant =  harq_entity->harq_process[pid].tb[tid].grant;
            if ((cur_grant.ndi_present&&(cur_grant.ndi != last_grant.ndi))||
            (last_grant.is_first_transmission == true||
            (last_grant.tbs != cur_grant.tbs)))
            {
                locked = harq_entity->harq_process[pid].tb[tid].using_mutex.try_lock();
                if (locked) {return DL_SNIFFER_NEW_TX;}
                else {
                    return DL_SNIFFER_HARQ_BUSY;
                }
            } else {
                bool is_decoded = harq_entity->harq_process[pid].tb[tid].grant.last_decoded;
                if (!is_decoded) {
                    locked = harq_entity->harq_process[pid].tb[tid].using_mutex.try_lock();
                    if (locked) {return DL_SNIFFER_RE_TX;}
                    else {
                        return DL_SNIFFER_HARQ_BUSY;
                    }
                } else {
                    return DL_SNIFFER_DECODED;
                }
            }
        }
    }
    harq_lock.unlock();
}

srsran_softbuffer_rx_t* HARQ::getHARQBuffer(uint16_t RNTI, int pid, int tid)
{
    std::unique_lock<std::mutex> harq_lock(harq_mutex);
    srsran_softbuffer_rx_t* tem_buffer;
    bool found = false;
    std::vector<std::shared_ptr<dl_sniffer_harq_entity_t>>::iterator iter;
    for (iter = harq_database.begin(); iter != harq_database.end(); iter++){
        if ((*iter)->rnti == RNTI){
            tem_buffer = (*iter)->harq_process[pid].tb[tid].buffer;
            found = true;
        }
    }
    harq_lock.unlock();
    return tem_buffer;
}

void HARQ::updateProcess(int pid,
                         int tid,
                         uint32_t sfn,
                         uint32_t sf_idx,
                         dl_sniffer_harq_grant_t cur_grant,
                         dl_sniffer_harq_entity_t *harq_entity)
{
    clock_t cur_time = clock();
    harq_entity->time = cur_time;
    harq_entity->harq_process[pid].tb[tid].sfn = sfn;
    harq_entity->harq_process[pid].tb[tid].sf_idx = sf_idx;
    harq_entity->harq_process[pid].tb[tid].grant = cur_grant;
}

void HARQ::updateHARQRNTI(uint16_t RNTI, 
                            int pid,
                            int tid,
                            uint32_t sfn,
                            uint32_t sf_idx,
                            dl_sniffer_harq_grant_t cur_grant)
{
    std::unique_lock<std::mutex> harq_lock(harq_mutex);
    bool found = false;
    std::vector<std::shared_ptr<dl_sniffer_harq_entity_t>>::iterator iter;
    for (iter = harq_database.begin(); iter != harq_database.end(); iter++){
        if ((*iter)->rnti == RNTI){
            updateProcess(pid, tid, sfn, sf_idx, cur_grant, (*iter).get());
            found = true;
            (*iter)->harq_process[pid].tb[tid].using_mutex.unlock();
        }
    }
    if (found = false){
        //add RNTI
    }
    harq_lock.unlock();
}

void HARQ::updateStatisticRNTI(uint16_t RNTI, 
                             int pid,
                             bool is_retx,
                             bool success)
{
    std::unique_lock<std::mutex> harq_lock(harq_mutex);
    std::vector<std::shared_ptr<dl_sniffer_harq_entity_t>>::iterator iter;
    for (iter = harq_database.begin(); iter != harq_database.end(); iter++){
        if ((*iter)->rnti == RNTI){
            (*iter)->nof_active++;
            if (success){ (*iter)->nof_success++; }
            if (is_retx){ (*iter)->harq_process[pid].nof_retx++;}
            if (success&&is_retx) { (*iter)->nof_retx_success++;}
        }
    }
    harq_lock.unlock();
}

void HARQ::updateHARQDatabase()
{
    std::unique_lock<std::mutex> harq_lock(harq_mutex);
    //printf("[HARQ] Updating HARQ database\n");
    clock_t cur_time = clock();
    if (nof_aval <= 10){
        //printf("[HARQ] Avail size < 10, updating database\n");
        std::vector<std::shared_ptr<dl_sniffer_harq_entity_t>>::iterator iter;
        for (iter = harq_database.begin(); iter != harq_database.end(); iter++){
            long double cur_interval = (long double)((cur_time - (*iter)->time)/CLOCKS_PER_SEC);
            if (cur_interval > interval){
                (*iter)->rnti = 0;
                (*iter)->time = 0;
                for (int i = 0; i < DL_SNIFFER_MAX_HARQ_PROCESS; i++){
                    for (int j = 0; j < SRSRAN_MAX_CODEWORDS; j++){
                        (*iter)->harq_process[i].tb[j].using_mutex.lock();
                        (*iter)->harq_process[i].tb[j].grant.is_first_transmission = true;
                        (*iter)->harq_process[i].tb[j].grant.last_decoded = false;
                        (*iter)->harq_process[i].tb[j].grant.tbs = 0;
                        (*iter)->harq_process[i].tb[j].sf_idx = 0;
                        (*iter)->harq_process[i].tb[j].sf_idx = 0;
                        //srsran_softbuffer_rx_reset((*iter)->harq_process[i].tb[j].buffer);
                        (*iter)->harq_process[i].tb[j].using_mutex.unlock();
                    }
                }
                nof_aval++;
            }
        }
    }
    //printf("[HARQ] Update HARQ database finished, nof_members: %d\n", harqBufferSize());
    harq_lock.unlock();
}

void HARQ::printHARQDatabase(){
    std::unique_lock<std::mutex> harq_lock(harq_mutex);
    std::vector<std::shared_ptr<dl_sniffer_harq_entity_t>>::iterator iter;
    int nof_total_retx = 0;
    for (iter = harq_database.begin(); iter != harq_database.end(); iter++){
        int nof_retx = 0;
        if ((*iter)->rnti!=0){
            printf("[HARQ] RNTI %d:", (*iter)->rnti);
            for (int i = 0; i < DL_SNIFFER_MAX_HARQ_PROCESS; i++){
                nof_retx = nof_retx + (*iter)->harq_process[i].nof_retx;
                nof_total_retx = nof_total_retx + (*iter)->harq_process[i].nof_retx;
                //printf(", process %d: %d", i, harq_entity->harq_process[i].nof_retx);
            }
            printf(" -- total: %d reTX -- nof_retx_success: %d -- nof_active: %d -- nof_success: %d\n",
                nof_retx, (*iter)->nof_retx_success, (*iter)->nof_active, (*iter)->nof_success);
        }
    }
    printf("[HARQ] Total reTX for all RNTIs: %d \n", nof_total_retx);
    harq_lock.unlock();
}

int HARQ::getlastTbs(uint16_t RNTI, int pid, int tid)
{
    std::unique_lock<std::mutex> harq_lock(harq_mutex);
    std::vector<std::shared_ptr<dl_sniffer_harq_entity_t>>::iterator iter;
    int tbs = 0;
    for (iter = harq_database.begin(); iter != harq_database.end(); iter++){
        if ((*iter)->rnti == RNTI){
            tbs = (*iter)->harq_process[pid].tb[tid].grant.tbs;
        }
    }
    harq_lock.unlock();
    return tbs;
}

/*----------------- UL HARQ implementation------------------*/

UL_HARQ::UL_HARQ()
{

}
UL_HARQ::~UL_HARQ()
{

}

void UL_HARQ::updateHARQRNTI(uint16_t RNTI, 
                             uint32_t sfn,
                             uint32_t sf_idx,
                             int decode_result,
                             DCI_UL cur_dci_ul)
{
    std::unique_lock<std::mutex> harq_lock(ul_harq_mutex);
    bool found = false;
    clock_t cur_time = clock();
    std::vector<std::shared_ptr<ul_sniffer_harq_t>>::iterator iter;
    for (iter = ul_harq_database.begin(); iter != ul_harq_database.end(); iter++){
        if ((*iter)->rnti == RNTI){
            //printf( "Found RNTI: %d in data base \n", RNTI);
            found = true;
            (*iter)->tti = sfn*10 + sf_idx;
            (*iter)->last_dci_ul = cur_dci_ul;
            (*iter)->time = cur_time;
            (*iter)->decode_result = decode_result;
            (*iter)->phich_grant.I_phich = 0;
            (*iter)->phich_grant.n_dmrs = cur_dci_ul.ran_ul_grant->n_dmrs;
            (*iter)->phich_grant.n_prb_lowest = cur_dci_ul.ran_ul_grant->n_prb_tilde[0];
        }
    }
    if (found == false){
        //add RNTI
        //printf( "Adding RNTI: %d \n", RNTI);
        ul_sniffer_harq_t new_ul_harq = {};
        new_ul_harq.rnti = RNTI;
        new_ul_harq.time =cur_time;
        new_ul_harq.last_dci_ul = cur_dci_ul;
        new_ul_harq.tti = sfn*10 + sf_idx;
        new_ul_harq.decode_result = decode_result;
        new_ul_harq.phich_grant.I_phich = 0;
        new_ul_harq.phich_grant.n_dmrs = cur_dci_ul.ran_ul_grant->n_dmrs;
        new_ul_harq.phich_grant.n_prb_lowest = cur_dci_ul.ran_ul_grant->n_prb_tilde[0];
        ul_harq_database.push_back(std::make_shared<ul_sniffer_harq_t>(new_ul_harq));
    }
    harq_lock.unlock();
}
