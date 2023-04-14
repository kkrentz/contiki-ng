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
 *         Basic UDP client for experimentation.
 * \author
 *         Konrad Krentz <konrad.krentz@gmail.com>
 */

#include "contiki.h"
#include "contiki-net.h"
#include "net/ipv6/simple-udp.h"
#include "net/ipv6/uip-ds6.h"
#include "net/mac/wake-up-counter.h"
#include "sys/node-id.h"

#include "sys/log.h"
#define LOG_MODULE "Client"
#define LOG_LEVEL LOG_LEVEL_INFO

#define UDP_CLIENT_PORT 8765
#define UDP_SERVER_PORT 5678

PROCESS(client_process, "client_process");
AUTOSTART_PROCESSES(&client_process);
#ifndef MUTE
static struct simple_udp_connection connection;
static const uip_lladdr_t server_lladdr = {
#if LINKADDR_SIZE == 2
  { 0x00, 0x01 }
#else /* LINKADDR_SIZE == 2 */
  { 0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01 }
#endif /* LINKADDR_SIZE == 2 */
  };
#endif /* !MUTE */

/*---------------------------------------------------------------------------*/
PROCESS_THREAD(client_process, ev, data)
{
  static uint32_t counter;
  static struct etimer t;

  PROCESS_BEGIN();

  LOG_INFO("%u started\n", node_id);
  if(node_id == ROOT_NODE_ID) {
    NETSTACK_ROUTING.root_start();
  }

#ifndef MUTE
  simple_udp_register(&connection,
                      UDP_CLIENT_PORT,
                      NULL,
                      UDP_SERVER_PORT,
                      NULL);
#endif /* !MUTE */

  etimer_set(&t, CLOCK_SECOND * 60 * 10);
  while(1) {
    PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&t));
    if(counter == 100) {
      LOG_INFO("1 third\n");
    } else if(counter == 200) {
      LOG_INFO("2 thirds\n");
    } else if(counter == 300) {
      LOG_INFO("done\n");
      break;
    }

    counter++;

#ifndef MUTE
    uip_ipaddr_t server_ipaddr;
    if(NETSTACK_ROUTING.node_is_reachable()
       && NETSTACK_ROUTING.get_root_ipaddr(&server_ipaddr)) {
      uip_ds6_set_addr_iid(&server_ipaddr, &server_lladdr);
      rtimer_clock_t now = RTIMER_NOW();
      uint8_t payload[64];
      memcpy(payload, &counter, sizeof(counter));
      memcpy(payload + sizeof(counter), &now, sizeof(rtimer_clock_t));
      simple_udp_sendto(&connection, payload, sizeof(payload), &server_ipaddr);
    }
#endif /* !MUTE */

    etimer_set(&t,
               CLOCK_SECOND * 10
               + clock_random((CLOCK_SECOND / WAKE_UP_COUNTER_RATE) * 16));
  }

  PROCESS_END();
}
/*---------------------------------------------------------------------------*/
