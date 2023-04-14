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
#define LOG_LEVEL LOG_LEVEL_INFO

#define UDP_SERVER_PORT 5678
#define UDP_CLIENT_PORT 8765

PROCESS(server_process, "server_process");
AUTOSTART_PROCESSES(&server_process);
#ifndef MUTE
static struct simple_udp_connection connection;
extern linkaddr_t llsender;

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
  rtimer_clock_t reception_time = RTIMER_NOW();
  uint32_t counter;
  memcpy(&counter, data, sizeof(counter));
  rtimer_clock_t send_time;
  memcpy(&send_time, data + sizeof(counter), sizeof(send_time));
  printf("D,%" RTIMER_PRI ",%" PRIu32 ",%" RTIMER_PRI ",%u\n",
         reception_time,
         counter,
         reception_time - send_time,
         llsender.u8[1]);
}
#endif /* !MUTE */
/*---------------------------------------------------------------------------*/
PROCESS_THREAD(server_process, ev, data)
{
  PROCESS_BEGIN();

  LOG_INFO("%u started\n", node_id);
  if(node_id == ROOT_NODE_ID) {
    NETSTACK_ROUTING.root_start();
  }

  printf("D,time,datagram,delay,forwarder\n");
#ifndef MUTE
  simple_udp_register(&connection,
                      UDP_SERVER_PORT,
                      NULL,
                      UDP_CLIENT_PORT,
                      callback);
#endif /* !MUTE */

  PROCESS_END();
}
/*---------------------------------------------------------------------------*/
