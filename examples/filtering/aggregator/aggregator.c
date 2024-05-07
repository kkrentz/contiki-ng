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

#include "contiki.h"
#include "filtering-client.h"
#include "net/ipv6/uip.h"
#include "net/packetbuf.h"
#include <coap3/coap.h>

#include "sys/log.h"
#define LOG_MODULE "Aggregator"
#define LOG_LEVEL LOG_LEVEL_INFO

#define UDP_HEADER_LENGTH (8)

static void on_registered(coap_context_t *context);

PROCESS(contiki_ng_br, "Contiki-NG Border Router");
AUTOSTART_PROCESSES(&contiki_ng_br);
static filtering_client_subscription_t observer = { NULL , on_registered };

/*---------------------------------------------------------------------------*/
PROCESS_THREAD(contiki_ng_br, ev, data)
{
  PROCESS_BEGIN();

  filtering_client_start();
  filtering_client_subscribe(&observer);

  LOG_INFO("Aggregator started\n");

  PROCESS_END();
}
/*---------------------------------------------------------------------------*/
static void
on_registered(coap_context_t *context)
{
  LOG_INFO("Aggregator registered\n");
}
/*---------------------------------------------------------------------------*/
int
aggregator_prefilter(void)
{
  /* skip over IPv6 extension headers */
  uint8_t protocol;
  uint8_t *next_header = uipbuf_get_next_header(uip_buf,
      uip_len,
      &protocol,
      true);
  while(next_header && uip_is_proto_ext_hdr(protocol)) {
    next_header = uipbuf_get_next_header(next_header,
        uip_len - (next_header - uip_buf),
        &protocol,
        false);
  }
  if(!next_header) {
    return 0;
  }

  /* inspect payload */
  switch(protocol) {
  case UIP_PROTO_TCP:
    LOG_ERR("Dropping TCP segment\n");
    return 0;
  case UIP_PROTO_UDP:
    {
      /* validate UDP header */
      size_t remaining_length = uip_len - (next_header - uip_buf);
      if(remaining_length < UDP_HEADER_LENGTH) {
        LOG_ERR("Invalid UDP datagram\n");
        return 0;
      }
      next_header += UDP_HEADER_LENGTH;
      remaining_length -= UDP_HEADER_LENGTH;

      /* parse CoAP message */
      coap_pdu_t *pdu = coap_pdu_init(0, 0, 0, remaining_length);
      if(!pdu) {
        LOG_ERR("coap_pdu_init failed\n");
        return 0;
      }
      if(!coap_pdu_parse(COAP_PROTO_UDP, next_header, remaining_length, pdu)) {
        LOG_ERR("coap_pdu_parse failed\n");
        coap_delete_pdu(pdu);
        return 0;
      }
      /* look for OSCORE option */
      coap_opt_iterator_t oi;
      coap_pdu_code_t code = coap_pdu_get_code(pdu);
      if(coap_check_option(pdu, COAP_OPTION_OSCORE, &oi)
          && (code != COAP_RESPONSE_CODE_CONTENT)) {
        if (code && (code < 32)) {
          uipbuf_set_attr_flag(UIPBUF_ATTR_FLAGS_INBOUND_OSCORE_REQUEST);
        } else {
          uipbuf_set_attr_flag(UIPBUF_ATTR_FLAGS_INBOUND_OSCORE_RESPONSE);
        }
        uipbuf_set_attr(UIPBUF_ATTR_COAP_MESSAGE_ID, coap_pdu_get_mid(pdu));
      } else {
        /* TODO rate limit */
      }
      coap_delete_pdu(pdu);
    }
    break;
  case UIP_PROTO_ICMP6:
    /* TODO rate limit */
    break;
  }
  return 1;
}
/*---------------------------------------------------------------------------*/
void
aggregator_update_attributes(void)
{
  if(uipbuf_is_attr_flag(UIPBUF_ATTR_FLAGS_INBOUND_OSCORE_REQUEST)) {
    packetbuf_set_attr(PACKETBUF_ATTR_INBOUND_OSCORE,
        UIPBUF_ATTR_FLAGS_INBOUND_OSCORE_REQUEST);
  } else if(uipbuf_is_attr_flag(UIPBUF_ATTR_FLAGS_INBOUND_OSCORE_RESPONSE)) {
    packetbuf_set_attr(PACKETBUF_ATTR_INBOUND_OSCORE,
        UIPBUF_ATTR_FLAGS_INBOUND_OSCORE_RESPONSE);
  }
  packetbuf_set_attr(PACKETBUF_ATTR_COAP_MESSAGE_ID,
      uipbuf_get_attr(UIPBUF_ATTR_COAP_MESSAGE_ID));
}
/*---------------------------------------------------------------------------*/
