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
#include <coap3/coap.h>

#include "sys/log.h"
#define LOG_MODULE "echo-client"
#define LOG_LEVEL LOG_LEVEL_NONE

#define UDP_CLIENT_PORT 8765
#define UDP_SERVER_PORT 5678

static coap_response_t on_echo(coap_session_t *session,
                               const coap_pdu_t *request,
                               const coap_pdu_t *response,
                               const coap_mid_t mid);

PROCESS(echo_client_process, "echo_client_process");
AUTOSTART_PROCESSES(&echo_client_process);
static const uip_lladdr_t server_lladdr = {
#if LINKADDR_SIZE == 2
  { 0x00, 0x01 }
#else /* LINKADDR_SIZE == 2 */
  { 0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01 }
#endif /* LINKADDR_SIZE == 2 */
};

/*---------------------------------------------------------------------------*/
PROCESS_THREAD(echo_client_process, ev, data)
{
  static struct etimer t;
  coap_context_t *context;
  coap_address_t server_address;
  static coap_session_t *session;
  static uint32_t counter;
  coap_pdu_t *pdu;

  PROCESS_BEGIN();

  LOG_INFO("%u started\n", node_id);

  etimer_set(&t, CLOCK_SECOND * 60 * 10);
  PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&t));

  context = coap_new_context(NULL);
  if(!context) {
    LOG_ERR("coap_new_context failed\n");
    PROCESS_EXIT();
  }
  if(!NETSTACK_ROUTING.node_is_reachable()
     || !NETSTACK_ROUTING.get_root_ipaddr(&server_address.addr)) {
    LOG_ERR("still not reachable\n");
    coap_free_context(context);
    PROCESS_EXIT();
  }
  uip_ds6_set_addr_iid(&server_address.addr, &server_lladdr);
  coap_address_set_port(&server_address, 5683);
  session = coap_new_client_session(context,
                                    NULL,
                                    &server_address,
                                    COAP_PROTO_UDP);
  if(!session) {
    LOG_ERR("coap_new_client_session failed\n");
    coap_free_context(context);
    PROCESS_EXIT();
  }
  coap_session_set_mtu(session, 128);
  coap_register_response_handler(context, on_echo);

  while(1) {
    if(counter == 10) {
      LOG_INFO("done\n");
      break;
    }

    counter++;

    pdu = coap_pdu_init(COAP_MESSAGE_CON,
                        COAP_REQUEST_CODE_GET,
                        coap_new_message_id(session),
                        coap_session_max_pdu_size(session));
    if(pdu) {
      coap_add_option(pdu, COAP_OPTION_URI_PATH, 4, (const uint8_t *)"echo");
      coap_add_data(pdu, sizeof(counter), (const uint8_t *)&counter);
      coap_send(session, pdu);
    }

    etimer_set(&t,
               CLOCK_SECOND * 10
               + clock_random((CLOCK_SECOND / WAKE_UP_COUNTER_RATE) * 16));
    PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&t));
  }

  PROCESS_END();
}
/*---------------------------------------------------------------------------*/
static coap_response_t
on_echo(coap_session_t *session,
        const coap_pdu_t *request,
        const coap_pdu_t *response,
        const coap_mid_t mid)
{
  size_t payload_length;
  const uint8_t *payload;
  uint32_t counter;

  coap_get_data(response, &payload_length, &payload);
  if(payload_length != sizeof(counter)) {
    return COAP_RESPONSE_FAIL;
  }
  memcpy(&counter, payload, payload_length);
  printf("received %u\n", counter);
  return COAP_RESPONSE_OK;
}
/*---------------------------------------------------------------------------*/
