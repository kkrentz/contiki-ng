/*
 * Copyright (c) 2021, Uppsala universitet.
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
 *         Demonstrates the usage of libcoap.
 * \author
 *         Konrad Krentz <konrad.krentz@gmail.com>
 */

#include "net/linkaddr.h"
#include "net/ipv6/uip-ds6.h"
#include "net/routing/routing.h"
#include <coap3/coap.h>

/* Log configuration */
#include "sys/log.h"
#define LOG_MODULE "CoAP-Demo"
#define LOG_LEVEL LOG_LEVEL_COAP

#if COAP_OSCORE_NG_SUPPORT
static const uint8_t master_secret[] = {
  0x0 , 0x1 , 0x2 , 0x3 , 0x4 , 0x5 , 0x6 , 0x7 ,
  0x8 , 0x9 , 0xA , 0xB , 0xC , 0xD , 0xE , 0xF
};
static const coap_oscore_ng_keying_material_t keying_material = {
  { sizeof(master_secret), master_secret }, { 0, NULL}
};
static const uint8_t sender_id_bytes[] = { 0xA };
static const coap_bin_const_t sender_id = {
  sizeof(sender_id_bytes) , sender_id_bytes
};
static const uint8_t recipient_id_bytes[] = { 0xB };
static const coap_bin_const_t recipient_id = {
  sizeof(recipient_id_bytes) , recipient_id_bytes
};
#endif /* COAP_OSCORE_NG_SUPPORT */

#if COAP_OSCORE_SUPPORT
static const char config_string[] =
    "master_secret,hex,000102030405060708090A0B0C0D0E0F\n"
    "sender_id,hex,0A\n"
    "recipient_id,hex,0B\n"
    "rfc8613_b_1_2,bool,false\n"
    "rfc8613_b_2,bool,false\n";
#endif /* COAP_OSCORE_SUPPORT */

static void hello(coap_resource_t *resource,
    coap_session_t *session,
    const coap_pdu_t *request,
    const coap_string_t *query,
    coap_pdu_t *response);

PROCESS(server_process, "server_process");
AUTOSTART_PROCESSES(&server_process);

/*---------------------------------------------------------------------------*/
#if COAP_OSCORE_NG_SUPPORT
static const coap_oscore_ng_keying_material_t *
get_keying_material(const coap_bin_const_t *ri)
{
  return coap_binary_equal(ri, &recipient_id) ? &keying_material: NULL;
}
#endif /* COAP_OSCORE_NG_SUPPORT */
/*---------------------------------------------------------------------------*/
PROCESS_THREAD(server_process, ev, data)
{
  PROCESS_BEGIN();

  /* turn into root node */
  uip_ipaddr_t global_prefix = { .u16 = { UIP_HTONS(UIP_DS6_DEFAULT_PREFIX) } };
  uip_ipaddr_t iid;
  uip_ds6_set_addr_iid(&iid, (const uip_lladdr_t *)&linkaddr_node_addr);
  NETSTACK_ROUTING.root_set_prefix(&global_prefix, &iid);
  NETSTACK_ROUTING.root_start();

  /* create CoAP context */
  coap_context_t *context = coap_new_context(NULL);
  if(!context) {
    LOG_ERR("coap_new_context failed\n");
    PROCESS_EXIT();
  }
  coap_context_set_max_idle_sessions(context, 1);
  coap_context_set_session_timeout(context, 60 * 15);

  /* create endpoint */
  uip_ds6_addr_t *my_address = uip_ds6_get_global(ADDR_PREFERRED);
  coap_address_t my_coap_address;
  uip_ipaddr_copy(&my_coap_address.addr, &my_address->ipaddr);
  coap_address_set_port(&my_coap_address, 5683);
  coap_endpoint_t *endpoint = coap_new_endpoint(context,
      &my_coap_address,
      COAP_PROTO_UDP);
  if(!endpoint) {
    LOG_ERR("coap_new_endpoint failed\n");
    coap_free_context(context);
    PROCESS_EXIT();
  }

  /* init OSCORE(-NG) */
#if COAP_OSCORE_SUPPORT
  coap_oscore_conf_t *config_structure =
      coap_new_oscore_conf(*coap_make_str_const(config_string), NULL, NULL, 0);
  if(!config_structure) {
    LOG_ERR("coap_new_oscore_conf failed\n");
    coap_free_context(context);
    PROCESS_EXIT();
  }
  if(!coap_context_oscore_server(context, config_structure)) {
    LOG_ERR("coap_context_oscore_server failed\n");
    coap_free_context(context);
    PROCESS_EXIT();
  }
#endif /* COAP_OSCORE_SUPPORT */
#if COAP_OSCORE_NG_SUPPORT
  if(!coap_oscore_ng_init(context, get_keying_material, &sender_id)) {
    LOG_ERR("coap_oscore_ng_init failed\n");
    coap_free_context(context);
    PROCESS_EXIT();
  }
#endif /* COAP_OSCORE_NG_SUPPORT */

  /* init resource */
  coap_str_const_t *ruri = coap_make_str_const("hello");
  int resource_flags = 0;
#if COAP_OSCORE_SUPPORT
  resource_flags |= COAP_RESOURCE_FLAGS_OSCORE_ONLY;
#endif /* COAP_OSCORE_NG_SUPPORT */
#if COAP_OSCORE_NG_SUPPORT
   resource_flags |= COAP_RESOURCE_FLAGS_OSCORE_NG_ONLY;
#endif /* COAP_OSCORE_NG_SUPPORT */
  coap_resource_t *resource = coap_resource_init(ruri, resource_flags);
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
