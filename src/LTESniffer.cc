
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
  cout << "LTESniffer" << endl;
  cout << endl;

  Args args;
  ArgManager::parseArgs(args, argc, argv);

  //attach signal handlers (for CTRL+C)
  SignalGate& signalGate(SignalGate::getInstance());
  signalGate.init();

  LTESniffer_Core SnifferCore(args);
  signalGate.attach(SnifferCore);

  bool success = SnifferCore.run();

  return success ? EXIT_SUCCESS : EXIT_FAILURE;
}
