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

#include "net/linkaddr.h"
#include "contiki-net.h"
#include <coap3/coap.h>

/* Log configuration */
#include "sys/log.h"
#define LOG_MODULE "echo-server"
#define LOG_LEVEL LOG_LEVEL_DBG

static void echo(coap_resource_t *resource,
    coap_session_t *session,
    const coap_pdu_t *request,
    const coap_string_t *query,
    coap_pdu_t *response);

PROCESS(echo_server_process, "echo_server_process");
AUTOSTART_PROCESSES(&echo_server_process);

/*---------------------------------------------------------------------------*/
PROCESS_THREAD(echo_server_process, ev, data)
{
  static struct etimer periodic_timer;
  uip_ds6_addr_t *my_address;
  coap_address_t my_coap_address;
  coap_context_t *context;
  coap_endpoint_t *endpoint;
  coap_str_const_t *ruri;
  coap_resource_t *resource;

  PROCESS_BEGIN();

  NETSTACK_ROUTING.root_start();

  /* wait for an IPv6 address */
  while(!NETSTACK_ROUTING.node_is_reachable()) {
    etimer_set(&periodic_timer, 5 * CLOCK_SECOND);
    PROCESS_WAIT_UNTIL(etimer_expired(&periodic_timer));
    LOG_INFO("Not reachable yet\n");
  }
  LOG_INFO("Became reachable\n");

  my_address = uip_ds6_get_global(ADDR_PREFERRED);
  uip_ipaddr_copy(&my_coap_address.addr, &my_address->ipaddr);
  coap_address_set_port(&my_coap_address, 5683);
  context = coap_new_context(NULL);
  if(!context) {
    LOG_ERR("coap_new_context failed\n");
    PROCESS_EXIT();
  }
  coap_context_set_max_idle_sessions(context, 1);
  endpoint = coap_new_endpoint(context, &my_coap_address, COAP_PROTO_UDP);
  if(!endpoint) {
    LOG_ERR("coap_new_endpoint failed\n");
    coap_free_context(context);
    PROCESS_EXIT();
  }
  coap_endpoint_set_default_mtu(endpoint, 128);
  ruri = coap_make_str_const("echo");
  resource = coap_resource_init(ruri, 0);
  if(!resource) {
    LOG_ERR("coap_resource_init failed\n");
    coap_free_context(context);
    PROCESS_EXIT();
  }
  coap_register_handler(resource, COAP_REQUEST_GET, echo);
  coap_add_resource(context, resource);

  PROCESS_END();
}
/*---------------------------------------------------------------------------*/
static void
echo(coap_resource_t *resource,
    coap_session_t *session,
    const coap_pdu_t *request,
    const coap_string_t *query,
    coap_pdu_t *response)
{
  size_t payload_length;
  const uint8_t *payload;

  coap_pdu_set_code(response, COAP_RESPONSE_CODE_CONTENT);
  coap_get_data(request, &payload_length, &payload);
  coap_add_data(response, payload_length, payload);
}
/*---------------------------------------------------------------------------*/
