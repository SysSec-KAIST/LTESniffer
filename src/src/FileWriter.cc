/*
 * LTE DL_Snifer BWS addition
 */

#include "include/FileWriter.h"

void LTESniffer_stat_writer::enable(bool en)
{
  enable_write = true; 
}
void LTESniffer_stat_writer::open(const std::string filename)
{
  fprintf(stdout, "Opening Statistic file\n");
  stat_file = fopen(filename.c_str(), "w");
  if (stat_file == NULL) {
    printf("Failed to open file \"%s\" for writing\n", filename.c_str());
  }
  enable_write    = true;
}

void LTESniffer_stat_writer::close()
{
  int err = -1;
  //fprintf(stdout, "Closing Statistic file\n");
  if (stat_file) {
    err = fclose(stat_file);
  }
  fprintf(stdout, "Closing Statistic file: success %d \n", err==0);
}

// public method
void LTESniffer_stat_writer::write_stats(std::string stats)
{
  writer(stats);
}

// private method
void LTESniffer_stat_writer::writer(std::string stats)
{
  std::unique_lock<std::mutex> lock(stat_mutex);
  if (enable_write) {
    if (stat_file == NULL) {
        /* Can't write if file wasn't successfully opened */
        printf("Error: Can't write to empty file handle\n");
    } else {
        /* Now write everything to the file                            */
        fwrite(stats.data(), sizeof(char), stats.size(), stat_file);
    }
  }
  lock.unlock();
}