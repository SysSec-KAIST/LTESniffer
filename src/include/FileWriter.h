/*
 * LTE DL_Snifer BWS addition
 */
#pragma once
#include <mutex>

// Define a new class for creating a new thread of stat
class LTESniffer_stat_writer
{
public:
    LTESniffer_stat_writer() {enable_write=false; stat_file = NULL; };
    void enable(bool en);
    void open(const std::string filename);
    void close();
    void write_stats(std::string); 
   
private:
    std::mutex stat_mutex;
    bool enable_write; 
    FILE *stat_file;
    void writer(std::string);
};