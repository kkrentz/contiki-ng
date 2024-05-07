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
#include "net/ipv6/uip-ds6.h"
#include "net/routing/routing.h"
#include <coap3/coap.h>

/* Log configuration */
#include "sys/log.h"
#define LOG_MODULE "CoAP-Demo"
#define LOG_LEVEL LOG_LEVEL_COAP

#ifdef OSCORE
static const oscore_ng_keying_material_t okm = {
  0 ,
  { 0x0 , 0x1 , 0x2 , 0x3 , 0x4 , 0x5 , 0x6 , 0x7 ,
    0x8 , 0x9 , 0xA , 0xB , 0xC , 0xD , 0xE , 0xF }
};
static const uint8_t sender_id[] = { 0x00 , 0x02 };
static const uint8_t allowed_recipient_id[] = { 0xA };
#endif

static void hello(coap_resource_t *resource,
    coap_session_t *session,
    const coap_pdu_t *request,
    const coap_string_t *query,
    coap_pdu_t *response);

PROCESS(destination_process, "Destination process");
AUTOSTART_PROCESSES(&destination_process);

/*---------------------------------------------------------------------------*/
#ifdef OSCORE
static const oscore_ng_keying_material_t *
get_keying_material(const uint8_t *recipient_id, uint8_t recipient_id_len)
{
  if((recipient_id_len != sizeof(allowed_recipient_id))
      || memcmp(recipient_id, allowed_recipient_id, recipient_id_len)) {
    return NULL;
  }
  return &okm;
}
#endif
/*---------------------------------------------------------------------------*/
PROCESS_THREAD(destination_process, ev, data)
{
#if !CONTIKI_TARGET_NATIVE
  static struct etimer periodic_timer;
#endif /* !CONTIKI_TARGET_NATIVE */
  uip_ds6_addr_t *my_address;
  coap_address_t my_coap_address;
  coap_context_t *context;
  coap_endpoint_t *endpoint;
  coap_str_const_t *ruri;
  coap_resource_t *resource;

  PROCESS_BEGIN();

#if !CONTIKI_TARGET_NATIVE
  /* wait for an IPv6 address */
  while(!NETSTACK_ROUTING.node_is_reachable()) {
    etimer_set(&periodic_timer, 5 * CLOCK_SECOND);
    PROCESS_WAIT_UNTIL(etimer_expired(&periodic_timer));
    LOG_INFO("Not reachable yet\n");
  }
  LOG_INFO("Became reachable\n");
#endif /* !CONTIKI_TARGET_NATIVE */

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
#ifdef OSCORE
  if(!coap_oscore_ng_init_endpoint(endpoint,
      get_keying_material,
      sender_id, sizeof(sender_id))) {
    LOG_ERR("coap_oscore_ng_init_endpoint failed\n");
    coap_free_context(context);
    PROCESS_EXIT();
  }
#endif
  ruri = coap_make_str_const("hello");
  resource = coap_resource_init(ruri, 0);
  if(!resource) {
    LOG_ERR("coap_resource_init failed\n");
    coap_free_context(context);
    PROCESS_EXIT();
  }
  coap_register_handler(resource, COAP_REQUEST_GET, hello);
  coap_add_resource(context, resource);

  PROCESS_END();
}
/*---------------------------------------------------------------------------*/
static void
hello(coap_resource_t *resource,
    coap_session_t *session,
    const coap_pdu_t *request,
    const coap_string_t *query,
    coap_pdu_t *response)
{
  coap_pdu_set_code(response, COAP_RESPONSE_CODE_CONTENT);
  coap_add_data(response, 5, (const uint8_t *)"world");
}
/*---------------------------------------------------------------------------*/
