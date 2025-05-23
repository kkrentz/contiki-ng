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

/**
 * \file
 *         Basic UDP client for experimentation.
 * \author
 *         Konrad Krentz <konrad.krentz@gmail.com>
 */

#include "contiki.h"
#include "contiki-net.h"
#include "net/ipv6/simple-udp.h"
#include "net/mac/wake-up-counter.h"
#include "sys/node-id.h"

#include "sys/log.h"
#define LOG_MODULE "Client"
#define LOG_LEVEL LOG_LEVEL_NONE

#define UDP_CLIENT_PORT 8765
#define UDP_SERVER_PORT 5678

PROCESS(client_process, "client_process");
AUTOSTART_PROCESSES(&client_process);
static struct simple_udp_connection connection;
static const uip_lladdr_t server_lladdr = {
#if LINKADDR_SIZE == 2
  { 0x00, 0x01 }
#else /* LINKADDR_SIZE == 2 */
  { 0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01 }
#endif /* LINKADDR_SIZE == 2 */
};

/*---------------------------------------------------------------------------*/
PROCESS_THREAD(client_process, ev, data)
{
  static uint32_t counter;
  static struct etimer t;

  PROCESS_BEGIN();

  LOG_INFO("%u started\n", node_id);

  simple_udp_register(&connection,
                      UDP_CLIENT_PORT,
                      NULL,
                      UDP_SERVER_PORT,
                      NULL);

  etimer_set(&t, CLOCK_SECOND * 60 * 10);
  while(1) {
    PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&t));
    if(counter == 10) {
      LOG_INFO("done\n");
      break;
    }

    counter++;

    uip_ipaddr_t server_ipaddr;
    if(NETSTACK_ROUTING.node_is_reachable()
       && NETSTACK_ROUTING.get_root_ipaddr(&server_ipaddr)) {
      uip_ds6_set_addr_iid(&server_ipaddr, &server_lladdr);
      simple_udp_sendto(&connection,
                        &counter,
                        sizeof(counter),
                        &server_ipaddr);
    }

    etimer_set(&t,
               CLOCK_SECOND * 10
               + clock_random((CLOCK_SECOND / WAKE_UP_COUNTER_RATE) * 16));
  }

  PROCESS_END();
}
/*---------------------------------------------------------------------------*/
