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

#include "contiki.h"
#include "contiki-net.h"
#include "sink-source.h"
#include "sys/energest.h"
#include "sys/etimer.h"
#include "sys/node-id.h"
#include <stdio.h>

#include "sys/log.h"
#define LOG_MODULE "Source"
#define LOG_LEVEL LOG_LEVEL_ERR

#ifdef SOURCE_CONF_RATE
#define SOURCE_RATE SOURCE_CONF_RATE
#else /* SOURCE_CONF_RATE */
#define SOURCE_RATE 25 /* 0.25 Hz */
#endif /* SOURCE_CONF_RATE */

PROCESS(source_process, "source_process");
AUTOSTART_PROCESSES(&source_process);

/*---------------------------------------------------------------------------*/
PROCESS_THREAD(source_process, ev, data)
{
  static struct etimer timeout;
  static struct etimer timer;
  static struct uip_udp_conn *conn;
  static uint32_t counter;

  PROCESS_BEGIN();

#if MAC_CONF_WITH_TSCH
  NETSTACK_MAC.on();
#endif /* MAC_CONF_WITH_TSCH */

  /* wait for the network to settle */
  etimer_set(&timer, WAITING_PERIOD * CLOCK_SECOND);
  PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&timer));

  /* set timeout */
  etimer_set(&timeout, SAMPLING_PERIOD * CLOCK_SECOND);

  while(1) {
    etimer_set(&timer, clock_random((2 * SOURCE_RATE * CLOCK_SECOND) / 10));
    PROCESS_WAIT_UNTIL(etimer_expired(&timer) || etimer_expired(&timeout));

    if(etimer_expired(&timeout)) {
      break;
    }

    printf("s;%" PRIu32 ";%02x%02x\n",
           ++counter,
           linkaddr_node_addr.u8[LINKADDR_SIZE - 2],
           linkaddr_node_addr.u8[LINKADDR_SIZE - 1]);

    if(!conn) {
      /* create UDP connection */
      if(!NETSTACK_ROUTING.node_is_reachable()) {
        continue;
      }
      uip_ipaddr_t sink_addr;
      if(!NETSTACK_ROUTING.get_root_ipaddr(&sink_addr)) {
        LOG_ERR("get_root_ipaddr failed\n");
        continue;
      }
      conn = uip_udp_new(&sink_addr, UIP_HTONS(SINK_PORT));
      if(!conn) {
        LOG_ERR("uip_udp_new failed\n");
        continue;
      }
    }

    uip_udp_packet_send(conn, &counter, sizeof(counter));
  }

  /* wait for the last transmissions to arrive */
  etimer_set(&timeout, FINISHING_PERIOD * CLOCK_SECOND);
  PROCESS_WAIT_UNTIL(etimer_expired(&timeout));

  /* close UDP connection */
  if(conn) {
    uip_udp_remove(conn);
  }

#if ENERGEST_CONF_ON
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
