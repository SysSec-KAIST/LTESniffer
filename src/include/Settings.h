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

// general
#define DIRECTION_UPLINK 0
#define DIRECTION_DOWNLINK 1

// network settings
#define DEFAULT_PROBING_URL_UPLINK    "http://129.217.211.19:6137/index.html"
#define DEFAULT_PROBING_URL_DOWNLINK  "http://129.217.211.19:6137/testfiles/100MB.bin"

#define DEFAULT_NETSYNC_PORT  4567

// probing settings
#define DEFAULT_NOF_SUBFRAMES_TO_CAPTURE 20000
#define DEFAULT_PROBING_DELAY_MS 10000
#define DEFAULT_PROBING_PAYLOAD_SIZE (5*1024*1024)
#define DEFAULT_PROBING_DIRECTION DIRECTION_UPLINK
#define DEFAULT_POLL_INTERVAL_SEC 1
#define DEFAULT_AUTO_INTERVAL_SEC 60
#define DEFAULT_TX_POWER_SAMPLING_INTERVAL_US 250000

#define DEFAULT_MIB_SEARCH_TIMEOUT_MS 1000
#define DEFAULT_PROBING_TIMEOUT_MS 10000

// eye settings
#define DEFAULT_NOF_SUBFRAMES_TO_SHOW 0
#define DEFAULT_NOF_PRB 50
#define DEFAULT_NOF_PORTS 2
#define DEFAULT_NOF_RX_ANT 1

#define DEFAULT_NOF_WORKERS 20
#define DEFAULT_NOF_THREAD 4

//#define DEFAULT_DCI_FORMAT_SPLIT_RATIO 1.0
#define DEFAULT_DCI_FORMAT_SPLIT_RATIO 0.99
#define DEFAULT_DCI_FORMAT_SPLIT_UPDATE_INTERVAL_MS 500
#define DEFAULT_RNTI_HISTOGRAM_THRESHOLD 5

