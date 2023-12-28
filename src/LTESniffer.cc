
#include "include/ArgManager.h"
#include "include/LTESniffer_Core.h"

#include "falcon/common/Version.h"
#include "falcon/common/SignalManager.h"

#include <iostream>
#include <memory>
#include <cstdlib>
#include <unistd.h>

using namespace std;

int main(int argc, char** argv) {
  cout << endl;
  cout << "LTESniffer Start!" << endl;
  cout << endl;

  // BWS
  auto now = std::chrono::system_clock::now();
  std::time_t cur_time = std::chrono::system_clock::to_time_t(now);
  std::string str_cur_time(std::ctime(&cur_time));
  for(std::string::iterator it = str_cur_time.begin(); it != str_cur_time.end(); ++it) {
    if (*it == ' '){
      *it = '_';
    } else if (*it == ':'){
      *it = '.';
    } else if (*it == '\n'){
      *it = '.';
    }
  }
  std::string error_filename = "LETTUCE_error_" + str_cur_time + "stat";
  FILE * myfile = freopen(error_filename.c_str(),"w",stderr);

  Args args;
  ArgManager::parseArgs(args, argc, argv);

  //attach signal handlers (for CTRL+C)
  SignalGate& signalGate(SignalGate::getInstance());
  signalGate.init();

  LTESniffer_Core SnifferCore(args);
  signalGate.attach(SnifferCore);

  bool success = SnifferCore.run();

  // BWS
  cout << endl;
  cout << "LTESniffer End!" << endl;
  cout << endl;
  myfile = freopen("/dev/tty","r",stderr);
  fclose (stderr);

  return success ? EXIT_SUCCESS : EXIT_FAILURE;
}
