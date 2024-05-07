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
 *         Demonstrates the usage of libcoap.
 * \author
 *         Konrad Krentz <konrad.krentz@gmail.com>
 */

#include "lib/aes-128.h"
#include "net/linkaddr.h"
#include "net/ipv6/uip-ds6.h"
#include "net/routing/routing.h"
#include <coap3/coap.h>

/* Log configuration */
#include "sys/log.h"
#define LOG_MODULE "CoAP-Demo"
#define LOG_LEVEL LOG_LEVEL_COAP

static coap_response_t on_response(coap_session_t *session,
                                   const coap_pdu_t *sent,
                                   const coap_pdu_t *received,
                                   const coap_mid_t mid);
static void on_pong(coap_session_t *session,
                    const coap_pdu_t *received,
                    const coap_mid_t mid);
static void on_timeout(coap_session_t *session,
                       const coap_pdu_t *sent,
                       const coap_nack_reason_t reason,
                       const coap_mid_t mid);

#if COAP_OSCORE_NG_SUPPORT
static const uint8_t master_secret[] = {
  0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7,
  0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF
};
static const coap_oscore_ng_keying_material_t keying_material = {
  { sizeof(master_secret), master_secret },
  { 0, NULL }
};
static const uint8_t sender_id_bytes[] = { 0xB };
static const coap_bin_const_t sender_id = {
  sizeof(sender_id_bytes), sender_id_bytes
};
static const uint8_t recipient_id_bytes[] = { 0xA };
static const coap_bin_const_t recipient_id = {
  sizeof(recipient_id_bytes), recipient_id_bytes
};
#endif /* COAP_OSCORE_NG_SUPPORT */

#if COAP_OSCORE_SUPPORT
static const char config_string[] =
    "master_secret,hex,000102030405060708090A0B0C0D0E0F\n"
    "sender_id,hex,0B\n"
    "recipient_id,hex,0A\n"
    "rfc8613_b_1_2,bool,false\n"
    "rfc8613_b_2,bool,false\n";
#endif /* COAP_OSCORE_SUPPORT */

static const uint8_t uri_path[] = "hello";
static const size_t uri_path_length = sizeof(uri_path) - 1;
PROCESS(client_process, "client_process");
AUTOSTART_PROCESSES(&client_process);

/*---------------------------------------------------------------------------*/
#if COAP_OSCORE_NG_SUPPORT
static const coap_oscore_ng_keying_material_t *
get_keying_material(const coap_bin_const_t *ri)
{
  return coap_binary_equal(ri, &recipient_id) ? &keying_material : NULL;
}
#endif /* COAP_OSCORE_NG_SUPPORT */
/*---------------------------------------------------------------------------*/
PROCESS_THREAD(client_process, ev, data)
{
  static struct etimer periodic_timer;
  static coap_context_t *context;
  static coap_session_t *session;

  PROCESS_BEGIN();

#if !CONTIKI_TARGET_NATIVE
  /* wait for an IPv6 address */
  while(!NETSTACK_ROUTING.node_is_reachable()) {
    etimer_set(&periodic_timer, 10 * CLOCK_SECOND);
    PROCESS_WAIT_UNTIL(etimer_expired(&periodic_timer));
    LOG_INFO("Not reachable yet\n");
  }
  LOG_INFO("Became reachable\n");
#endif /* !CONTIKI_TARGET_NATIVE */

  /* create CoAP context */
  context = coap_new_context(NULL);
  if(!context) {
    LOG_ERR("coap_new_context failed\n");
    PROCESS_EXIT();
  }
  coap_register_response_handler(context, on_response);
  coap_register_nack_handler(context, on_timeout);
  coap_register_pong_handler(context, on_pong);

  /* create session */
  {
    coap_address_t server_address;
    NETSTACK_ROUTING.get_root_ipaddr(&server_address.addr);
    coap_address_set_port(&server_address, 5683);
#if COAP_OSCORE_SUPPORT
    {
      coap_oscore_conf_t *config_structure =
          coap_new_oscore_conf(*coap_make_str_const(config_string),
                               NULL,
                               NULL,
                               0);
      if(!config_structure) {
        LOG_ERR("coap_new_oscore_conf failed\n");
        goto error;
      }
      session = coap_new_client_session_oscore(context,
                                               NULL,
                                               &server_address,
                                               COAP_PROTO_UDP,
                                               config_structure);
    }
    if(!session) {
      LOG_ERR("coap_new_client_session_oscore failed\n");
      goto error;
    }
#else /* COAP_OSCORE_SUPPORT */
    session = coap_new_client_session(context,
                                      NULL,
                                      &server_address,
                                      COAP_PROTO_UDP);
    if(!session) {
      LOG_ERR("coap_new_client_session failed\n");
      goto error;
    }
#endif /* COAP_OSCORE_SUPPORT */
  }
#if COAP_OSCORE_NG_SUPPORT
  if(!coap_oscore_ng_init(context, get_keying_material, &sender_id)) {
    LOG_ERR("coap_oscore_ng_init failed\n");
    goto error;
  }
  if(!coap_oscore_ng_init_client_session(session, &recipient_id, 1)) {
    LOG_ERR("coap_oscore_ng_init_client_session failed\n");
    goto error;
  }
#endif /* COAP_OSCORE_NG_SUPPORT */

  etimer_set(&periodic_timer, 10 * 60 * CLOCK_SECOND);

  /* send a PING to initiate the B2 protocol */
  if(coap_session_send_ping(session) == COAP_INVALID_MID) {
    LOG_ERR("coap_session_send_ping failed\n");
    goto error;
  }

  /* send requests */
  while(1) {
    PROCESS_WAIT_UNTIL(etimer_expired(&periodic_timer));
    coap_pdu_t *pdu = coap_pdu_init(COAP_MESSAGE_CON,
                                    COAP_REQUEST_CODE_GET,
                                    coap_new_message_id(session),
                                    coap_opt_encode_size(COAP_OPTION_URI_PATH,
                                                         uri_path_length));
    if(!pdu) {
      LOG_ERR("coap_pdu_init failed\n");
      goto error;
    }
    if(!coap_add_option(pdu,
                        COAP_OPTION_URI_PATH,
                        uri_path_length,
                        uri_path)) {
      LOG_ERR("coap_add_option failed\n");
      coap_delete_pdu(pdu);
      goto error;
    }
    coap_send(session, pdu);
    etimer_reset(&periodic_timer);
  }

error:
  coap_free_context(context);

  PROCESS_END();
}
/*---------------------------------------------------------------------------*/
static coap_response_t
on_response(coap_session_t *session,
            const coap_pdu_t *sent,
            const coap_pdu_t *received,
            const coap_mid_t mid)
{
  size_t payload_len;
  const uint8_t *payload_ptr;

  coap_get_data(received, &payload_len, &payload_ptr);
  LOG_DBG("response: ");
  while(payload_len--) {
    LOG_DBG_("%c", *payload_ptr);
    payload_ptr++;
  }
  LOG_DBG_("\n");

  return COAP_RESPONSE_OK;
}
/*---------------------------------------------------------------------------*/
static void
on_pong(coap_session_t *session,
        const coap_pdu_t *received,
        const coap_mid_t mid)
{
  LOG_INFO("on_pong\n");
}
/*---------------------------------------------------------------------------*/
static void
on_timeout(coap_session_t *session,
           const coap_pdu_t *sent,
           const coap_nack_reason_t reason,
           const coap_mid_t mid)
{
  LOG_ERR("on_timeout\n");
}
/*---------------------------------------------------------------------------*/
