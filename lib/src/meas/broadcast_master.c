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
#include "falcon/meas/broadcast_master.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

//#include <sys/socket.h>
//#include <netinet/in.h>
#include <arpa/inet.h>

void errno_abort(const char* header) {
  perror(header);
  exit(EXIT_FAILURE);
}

broadcast_master_t* broadcast_master_init(const char ip[], uint16_t port) {
  broadcast_master_t* h = calloc(1, sizeof (broadcast_master_t));

  int trueflag = 1;
  if ((h->fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
    errno_abort("socket");
  }

  if (setsockopt(h->fd, SOL_SOCKET, SO_BROADCAST, &trueflag, sizeof(trueflag)) < 0) {
    errno_abort("setsockopt");
  }

  memset(&h->send_addr, 0, sizeof(h->send_addr));
  h->send_addr.sin_family = AF_INET;
  h->send_addr.sin_port = (in_port_t)htons(port);
  inet_aton(ip, &h->send_addr.sin_addr);
  // send_addr.sin_addr.s_addr = htonl(INADDR_BROADCAST);

  memset(&h->recv_addr, 0, sizeof(h->recv_addr));

  return h;
}

void broadcast_master_destroy(broadcast_master_t* h) {
  if(h) {
    close(h->fd);
    h->fd = 0;
    free(h);
  }
}

size_t broadcast_master_receive(broadcast_master_t* h, char *msg, size_t len) {
  socklen_t recv_addr_len = sizeof (h->recv_addr);
  ssize_t recv_len = 0;
  recv_len = recvfrom(h->fd, msg, len, 0, (struct sockaddr*)&h->recv_addr, &recv_addr_len);
  if (recv_len < 0) {
    errno_abort("recv");
    recv_len = 0;
  }

  return (size_t)recv_len;
}

int32_t broadcast_master_send(broadcast_master_t* h, const char *msg, size_t len) {
  if (sendto(h->fd, msg, len, 0, (struct sockaddr*)&h->send_addr, sizeof(h->send_addr)) < 0) {
    errno_abort("send");
    return -1;
  }
  return 0;
}

int init_example(int argc, char* argv[])
{
#define SERVERPORT 4567
  struct sockaddr_in send_addr, recv_addr;
  int trueflag = 1, count = 0;
  int fd;
  if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
    errno_abort("socket");
  }
#ifndef RECV_ONLY
  if (setsockopt(fd, SOL_SOCKET, SO_BROADCAST,
                 &trueflag, sizeof trueflag) < 0)
    errno_abort("setsockopt");

  memset(&send_addr, 0, sizeof send_addr);
  send_addr.sin_family = AF_INET;
  send_addr.sin_port = (in_port_t) htons(SERVERPORT);
  // broadcasting address for unix (?)
  inet_aton("127.255.255.255", &send_addr.sin_addr);
  // send_addr.sin_addr.s_addr = htonl(INADDR_BROADCAST);
#endif // ! RECV_ONLY

#ifndef SEND_ONLY
  if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR,
                 &trueflag, sizeof trueflag) < 0)
    errno_abort("setsockopt");

  memset(&recv_addr, 0, sizeof recv_addr);
  recv_addr.sin_family = AF_INET;
  recv_addr.sin_port = (in_port_t) htons(SERVERPORT);
  recv_addr.sin_addr.s_addr = htonl(INADDR_ANY);

  if (bind(fd, (struct sockaddr*) &recv_addr, sizeof recv_addr) < 0)
    errno_abort("bind");
#endif // ! SEND_ONLY

  while ( 1 ) {
#ifndef RECV_ONLY
    char sbuf[256] = {};
    snprintf(sbuf, sizeof(sbuf), "Hello(%d)!", count++);
    if (sendto(fd, sbuf, strlen(sbuf)+1, 0,
               (struct sockaddr*) &send_addr, sizeof send_addr) < 0)
      errno_abort("send");
    printf("send: %s\n", sbuf);
    usleep(1000000/2);
#endif // ! RECV_ONLY

#ifndef SEND_ONLY
    char rbuf[256] = {};
    if (recv(fd, rbuf, sizeof(rbuf)-1, 0) < 0)
      errno_abort("recv");
    printf("recv: %s\n", rbuf);
#endif // ! SEND_ONLY
  }
  close(fd);
  return 0;
}
