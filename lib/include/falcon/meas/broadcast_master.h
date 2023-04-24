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

#ifdef __cplusplus
    extern "C" {
#endif

#include <netinet/ip.h>

typedef struct {
  int fd;
  struct sockaddr_in recv_addr;
  struct sockaddr_in send_addr;
} broadcast_master_t;

broadcast_master_t* broadcast_master_init(const char ip[], uint16_t port);
void broadcast_master_destroy(broadcast_master_t* h);
size_t broadcast_master_receive(broadcast_master_t* h, char *msg, size_t len);
int32_t broadcast_master_send(broadcast_master_t* h, const char* msg, size_t len);


int init_example(int argc, char* argv[]);

#ifdef __cplusplus
}
#endif
