/*
 * Copyright (c) 2023, Uppsala universitet.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the Institute nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * This file is part of the Contiki operating system.
 *
 */

/**
 * \file
 *         Basic UDP server for experimentation.
 * \author
 *         Konrad Krentz <konrad.krentz@gmail.com>
 */

#include "contiki.h"
#include "net/ipv6/simple-udp.h"
#include "contiki-net.h"
#include <stdio.h>
#include "sys/node-id.h"

#include "sys/log.h"
#define LOG_MODULE "Server"
#define LOG_LEVEL LOG_LEVEL_NONE

#define UDP_SERVER_PORT	5678
#define UDP_CLIENT_PORT 8765

PROCESS(server_process, "server_process");
AUTOSTART_PROCESSES(&server_process);
static struct simple_udp_connection connection;

/*---------------------------------------------------------------------------*/
static void
callback(struct simple_udp_connection *c,
    const uip_ipaddr_t *sender_ipaddr,
    uint16_t sender_port,
    const uip_ipaddr_t *receiver_ipaddr,
    uint16_t receiver_port,
    const uint8_t *data,
    uint16_t datalen)
{
  uint32_t counter;
  memcpy(&counter, data, sizeof(counter));
  printf("received %u\n", counter);
}
/*---------------------------------------------------------------------------*/
PROCESS_THREAD(server_process, ev, data)
{
  PROCESS_BEGIN();

  LOG_INFO("%u started\n", node_id);
  NETSTACK_ROUTING.root_start();

  simple_udp_register(&connection,
      UDP_SERVER_PORT,
      NULL,
      UDP_CLIENT_PORT,
      callback);

  PROCESS_END();
}
/*---------------------------------------------------------------------------*/
