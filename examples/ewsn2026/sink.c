/*
 * Copyright (c) 2026, Fraunhofer SIT
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
 * 3. Neither the name of the copyright holder nor the names of its
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "contiki-net.h"
#include "sink-source.h"
#include "sys/energest.h"
#include "sys/node-id.h"
#include <stdio.h>

#include "sys/log.h"
#define LOG_MODULE "Sink"
#define LOG_LEVEL LOG_LEVEL_ERR

PROCESS(sink_process, "sink_process");
AUTOSTART_PROCESSES(&sink_process);

/*---------------------------------------------------------------------------*/
PROCESS_THREAD(sink_process, ev, data)
{
  static struct etimer timeout;
  static struct uip_udp_conn *conn;

  PROCESS_BEGIN();

#if CONTIKI_TARGET_COOJA
  printf("t;name;event;counter;address\n");
#endif /* CONTIKI_TARGET_COOJA */

  etimer_set(&timeout,
             (WAITING_PERIOD + SAMPLING_PERIOD + FINISHING_PERIOD - 10)
             * CLOCK_SECOND);

  /* act as root */
  NETSTACK_ROUTING.root_start();

#if MAC_CONF_WITH_TSCH
  NETSTACK_MAC.on();
#endif /* MAC_CONF_WITH_TSCH */

  conn = udp_new(NULL, 0, NULL);
  if(!conn) {
    LOG_ERR("uip_udp_new failed\n");
    PROCESS_EXIT();
  }
  udp_bind(conn, UIP_HTONS(SINK_PORT));

  while(1) {
    PROCESS_WAIT_EVENT();
    if(etimer_expired(&timeout)) {
      break;
    }
    if(ev != tcpip_event) {
      continue;
    }
    if(!uip_newdata()) {
      continue;
    }
    uint32_t counter;
    if(uip_datalen() != sizeof(counter)) {
      continue;
    }
    memcpy(&counter, uip_appdata, sizeof(counter));
#if CONTIKI_TARGET_COOJA
    printf("%" CLOCK_PRI ";cooja-%" PRIu16 ";", clock_time(), node_id);
#endif /* CONTIKI_TARGET_COOJA */
    printf("r;%" PRIu32 ";%02x%02x\n",
           counter,
           UIP_IP_BUF->srcipaddr.u8[sizeof(UIP_IP_BUF->srcipaddr.u8) - 2],
           UIP_IP_BUF->srcipaddr.u8[sizeof(UIP_IP_BUF->srcipaddr.u8) - 1]);
  }

#if ENERGEST_CONF_ON
#if CONTIKI_TARGET_COOJA
  printf("%" CLOCK_PRI ";cooja-%" PRIu16 ";", clock_time(), node_id);
#endif /* CONTIKI_TARGET_COOJA */
  printf("energy;%02x%02x;%" PRIu64 ";%" PRIu64 ";%" RTIMER_PRI "\n",
         linkaddr_node_addr.u8[LINKADDR_SIZE - 2],
         linkaddr_node_addr.u8[LINKADDR_SIZE - 1],
         energest_type_time(ENERGEST_TYPE_LISTEN),
         energest_type_time(ENERGEST_TYPE_TRANSMIT),
         ENERGEST_CURRENT_TIME());
#endif /* ENERGEST_CONF_ON */

  PROCESS_END();
}
/*---------------------------------------------------------------------------*/
