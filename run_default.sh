#!/bin/bash
/home/LTESniffer_mirror/build/src/LTESniffer -a addr=192.168.30.2,type=x300,clock_source=external,time_source=external -d -A 2 -W 16 -f 2130e6 -u 1730e6 -C -m 2 -z 3 | tee /home/stats/LETTUCE_stdout_$(date '+%a_%b__%-d_%H.%M.%S_%Y').ansi
