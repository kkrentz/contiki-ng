/*
 * Copyright (c) 2021, Uppsala universitet.
 * Copyright (c) 2024, Siemens AG.
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
 * \addtogroup filtering
 * @{
 *
 * \file
 *         Remote attestation and key sharing.
 * \author
 *         Konrad Krentz <konrad.krentz@gmail.com>
 */

#include "filtering-client.h"
#include "coap3/coap_internal.h"
#include "lib/aes-128.h"
#include "lib/assert.h"
#include "lib/ccm-star.h"
#include "net/ipv6/uip-ds6.h"
#include "net/linkaddr.h"
#include "net/routing/routing.h"
#include "net/mac/csl/csl.h"
#include "net/mac/wake-up-counter.h"
#include "net/packetbuf.h"
#include <string.h>

#define WITH_CC_OPTIMIZATION \
  (CONTIKI_TARGET_CC2538DK || CONTIKI_TARGET_OPENMOTE || CONTIKI_TARGET_ZOUL)
#if WITH_CC_OPTIMIZATION
#define OTP_KEY_AREA (1)
#include "dev/crypto/cc/cc-aes-128.h"
#endif /* WITH_CC_OPTIMIZATION */

/* Log configuration */
#include "sys/log.h"
#define LOG_MODULE "Filtering"
#define LOG_LEVEL LOG_LEVEL_COAP

#define INACTIVITY_TIMEOUT (60 * 5) /* seconds */
#define PAYLOAD_MARKER_SIZE (1)
#define RELATES_TO_REQUEST_FLAG (1 << 7)
#define OTP_PAYLOAD_SIZE (1 + WAKE_UP_COUNTER_LEN + LINKADDR_SIZE + 2)

static void resume(void);
static int set_keying_material(const coap_bin_const_t *recipient_id,
                               const uint8_t *secret,
                               size_t secret_size);
static void clean_up(void);
static int init_libcoap(void);
static int disclose(
#if WITH_TRAP && !WITH_IRAP
    uint8_t clients_fhmqv_mic[COAP_RAP_FHMQV_MIC_SIZE]
#endif /* WITH_TRAP && !WITH_IRAP */
    );
static coap_response_t on_disclose_response(coap_session_t *session,
                                            const coap_pdu_t *sent,
                                            const coap_pdu_t *received,
                                            const coap_mid_t mid);
static void notify(void);
static int send_update(void);
static coap_response_t on_response(coap_session_t *session,
                                   const coap_pdu_t *sent,
                                   const coap_pdu_t *received,
                                   const coap_mid_t mid);
static void on_timeout(coap_session_t *session,
                       const coap_pdu_t *sent,
                       const coap_nack_reason_t reason,
                       const coap_mid_t mid);
#ifdef AGGREGATOR
static void on_got_otp_result(void *ptr);
#endif /* AGGREGATOR */

static const coap_bin_const_t middlebox_id = { 0, NULL };
#if WITH_TRAP
static const uint8_t my_public_key[2 * ECC_CURVE_P_256_SIZE] = {
  0xf7, 0x40, 0x9d, 0x80, 0x9d, 0x77, 0xc2, 0x29,
  0x70, 0xa1, 0x9f, 0x4f, 0xa9, 0x13, 0x5f, 0xfd,
  0x25, 0xc8, 0x2b, 0x4d, 0x88, 0xe0, 0x63, 0xbc,
  0x33, 0x9e, 0xaf, 0x46, 0x81, 0x3b, 0x87, 0xe1,
  0x29, 0xa6, 0x06, 0x9a, 0x5d, 0x86, 0x13, 0x8f,
  0x9f, 0xbb, 0x9f, 0x60, 0xf0, 0x35, 0x45, 0x87,
  0xbb, 0x34, 0x1d, 0x45, 0xf0, 0x31, 0x8f, 0xef,
  0x73, 0x6b, 0x8b, 0xd5, 0x7c, 0x7d, 0x11, 0xc2
};
#endif /* WITH_TRAP */
static const uint8_t my_private_key[ECC_CURVE_P_256_SIZE] = {
  0x64, 0x74, 0x92, 0xb6, 0xf6, 0x69, 0x8d, 0xc0,
  0x77, 0xb6, 0x52, 0x9a, 0xc1, 0xbd, 0x81, 0xe0,
  0xb6, 0xa6, 0xe2, 0xda, 0x6e, 0x6b, 0x2a, 0xe5,
  0x07, 0xd6, 0x05, 0x1f, 0x03, 0x3f, 0xfb, 0xae
};
static const uint8_t root_of_trusts_public_key[] = {
  0x07, 0x97, 0x95, 0x76, 0x0f, 0x3e, 0xbd, 0x66,
  0xfd, 0x75, 0x38, 0xa6, 0x46, 0x17, 0x85, 0xa3,
  0x4a, 0x07, 0x07, 0x75, 0xdc, 0xd8, 0xd3, 0x85,
  0x86, 0x4e, 0xbb, 0x4e, 0x38, 0x53, 0x69, 0x24,
  0x70, 0xe0, 0x93, 0xc1, 0xe7, 0xa7, 0x80, 0x15,
  0xee, 0x8d, 0x19, 0x87, 0x95, 0x5d, 0xb0, 0xc1,
  0x74, 0x8d, 0x66, 0x65, 0xfb, 0x6a, 0xa6, 0x90,
  0x46, 0x6f, 0xdd, 0xbf, 0x2b, 0x8d, 0x2d, 0x55,
};
static const uint8_t expected_sm_hash[] = {
  0xa9, 0x95, 0x41, 0x15, 0x98, 0xf5, 0xf2, 0x64,
  0xa6, 0x95, 0x95, 0x73, 0x8e, 0x15, 0x6e, 0x6c,
  0xed, 0x79, 0x94, 0x6d, 0x13, 0xd4, 0x14, 0x35,
  0xb8, 0xf2, 0xe4, 0x6d, 0x36, 0x8c, 0x7b, 0x82,
};
static const uint8_t expected_tee_hash[] = {
  0x51, 0xe0, 0xf2, 0x5c, 0xbe, 0x57, 0x43, 0xa9,
  0xdf, 0x67, 0x1b, 0x0a, 0x40, 0x45, 0xd7, 0xbf,
  0xf9, 0x4d, 0xae, 0x24, 0xa3, 0xa6, 0x0b, 0xd2,
  0x4e, 0xe0, 0x48, 0x56, 0x6d, 0x85, 0x71, 0xa5,
};
static const coap_rap_config_t rap_config = {
  resume,
  &middlebox_id,
  my_private_key,
#if WITH_TRAP
  my_public_key,
#endif /* WITH_TRAP */
  root_of_trusts_public_key,
  expected_sm_hash,
  expected_tee_hash,
#if WITH_IRAP
  1,
  1,
  NULL,
#endif /* WITH_IRAP */
  set_keying_material
};
static const uint8_t master_secret_to_share[AES_128_KEY_LENGTH] = {
  0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7,
  0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF
};
static const uint8_t disclose_uri[] = "dis";
static const uint8_t update_uri[] = "upd";
#ifdef AGGREGATOR
static const uint8_t otp_uri[] = "otp";
static struct pt pt;
#endif /* AGGREGATOR */
LIST(subscription_list);
static bool timeout_flag;
static coap_context_t *context;
static coap_session_t *session;
static bool is_connected;
static bool can_set_otp_key;
PROCESS(filtering_client_process, "filtering_client_process");
static struct etimer periodic_timer;
static uint8_t oscore_ng_key[AES_128_KEY_LENGTH];
static uint8_t otp_key[AES_128_KEY_LENGTH];
static coap_oscore_ng_keying_material_t km = {
  { sizeof(oscore_ng_key), oscore_ng_key }, { 0, NULL }
};
static struct etimer update_timer;
static coap_mid_t last_update_mid;
#ifdef AGGREGATOR
static bool got_result;
static bool got_filtering_otp;
static struct process *process_to_notify;
static uint8_t filtering_otp[CSL_FRAMER_POTR_OTP_LEN];
static struct ctimer otp_timeout;
static coap_mid_t last_otp_mid;
#endif /* AGGREGATOR */

/*---------------------------------------------------------------------------*/
static void
resume(void)
{
  process_poll(&filtering_client_process);
}
/*---------------------------------------------------------------------------*/
static const coap_oscore_ng_keying_material_t *
get_keying_material(const coap_bin_const_t *recipient_id)
{
  return coap_binary_equal(recipient_id, &middlebox_id) ? &km : NULL;
}
/*---------------------------------------------------------------------------*/
static int
set_keying_material(const coap_bin_const_t *recipient_id,
                    const uint8_t *secret,
                    size_t secret_size)
{
  if(!coap_binary_equal(recipient_id, &middlebox_id)) {
    return 0;
  }
  if(secret_size < (sizeof(oscore_ng_key) + sizeof(otp_key))) {
    return 0;
  }
  memcpy(oscore_ng_key, secret, sizeof(oscore_ng_key));
  memcpy(otp_key, secret + sizeof(oscore_ng_key), sizeof(otp_key));
  return 1;
}
/*---------------------------------------------------------------------------*/
PROCESS_THREAD(filtering_client_process, ev, data)
{
  PROCESS_BEGIN();

  context = coap_new_context(NULL);
  if(!context) {
    LOG_ERR("coap_new_context failed\n");
    PROCESS_EXIT();
  }
  {
    coap_bin_const_t my_id = {
      .length = LINKADDR_SIZE,
      .s = linkaddr_node_addr.u8
    };
    if(!coap_oscore_ng_init(context, get_keying_material, &my_id)) {
      LOG_ERR("coap_oscore_ng_init failed\n");
      coap_free_context(context);
      PROCESS_EXIT();
    }
  }

  while(1) {
    clean_up();

    /* wait for an IPv6 address */
    while(!NETSTACK_ROUTING.node_is_reachable()) {
      etimer_set(&periodic_timer, 5 * CLOCK_SECOND);
      PROCESS_WAIT_UNTIL(etimer_expired(&periodic_timer));
      LOG_INFO("Not reachable yet\n");
    }
    LOG_INFO("Became reachable\n");

    if(!init_libcoap()) {
      continue;
    }

    /* remote attestation & key exchange */
#if WITH_TRAP && !WITH_IRAP
    uint8_t clients_fhmqv_mic[COAP_RAP_FHMQV_MIC_SIZE];
#endif /* WITH_TRAP && !WITH_IRAP */
    PROCESS_PT_SPAWN(&session->rap_pt,
                     coap_rap_initiate(session,
                                       &rap_config
#if WITH_TRAP && !WITH_IRAP
                                       , clients_fhmqv_mic
#endif /* WITH_TRAP && !WITH_IRAP */
                                       ));
    if(!session->oscore_ng_context) {
      LOG_ERR("coap_rap failed\n");
      continue;
    }

#if WITH_CC_OPTIMIZATION
    /* store the OTP key in the key store for immediate access */
    while(!AES_128.get_lock());
    cc_aes_128_active_key_area = OTP_KEY_AREA;
    can_set_otp_key = AES_128.set_key(otp_key);
    cc_aes_128_active_key_area = CC_AES_128_KEY_AREA;
    AES_128.release_lock();
    if(!can_set_otp_key) {
      LOG_ERR("set_key failed\n");
      assert(false);
      continue;
    }
#else /* WITH_CC_OPTIMIZATION */
    can_set_otp_key = true;
#endif /* WITH_CC_OPTIMIZATION */

    /* share secrets */
    coap_register_nack_handler(context, on_timeout);
    coap_register_response_handler(context, on_disclose_response);
    if(!disclose(
#if WITH_TRAP && !WITH_IRAP
           clients_fhmqv_mic
#endif /* WITH_TRAP && !WITH_IRAP */
           )) {
      LOG_ERR("disclose failed\n");
      continue;
    }
    PROCESS_YIELD_UNTIL(ev == PROCESS_EVENT_POLL);
    if(timeout_flag) {
      continue;
    }

    /* suppress the kid context in subsequent OSCORE-NG messages */
    session->oscore_ng_context->has_explicit_id_context = false;

#ifdef AGGREGATOR
    last_otp_mid = COAP_INVALID_MID;
    ctimer_stop(&otp_timeout);
#endif /* AGGREGATOR */

    /* notify observers of successful remote attestation */
    is_connected = true;
    notify();

    /* send updates in the absence of messages from the middlebox */
    coap_register_response_handler(context, on_response);
    last_update_mid = COAP_INVALID_MID;
    filtering_client_prolong();
    while(1) {
      PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&update_timer));
      if(!send_update()) {
        LOG_ERR("send_update failed\n");
        break;
      }
      LOG_INFO("sent update\n");
      PROCESS_YIELD_UNTIL(ev == PROCESS_EVENT_POLL);
      if(timeout_flag) {
        break;
      }
    }
#ifdef AGGREGATOR
    PROCESS_WAIT_UNTIL(ctimer_expired(&otp_timeout));
#endif /* AGGREGATOR */
    is_connected = false;
  }

  PROCESS_END();
}
/*---------------------------------------------------------------------------*/
static void
clean_up(void)
{
  coap_session_release(session);
  session = NULL;
  can_set_otp_key = false;
  timeout_flag = false;
}
/*---------------------------------------------------------------------------*/
static int
init_libcoap(void)
{
  coap_address_t middlebox_address;
  uip_ip6addr(&middlebox_address.addr, 0xfd00, 0xabcd, 0, 0, 0, 0, 0, 2);
  coap_address_set_port(&middlebox_address, 5683);
  session = coap_new_client_session(context,
                                    NULL,
                                    &middlebox_address,
                                    COAP_PROTO_UDP);
  if(!session) {
    LOG_ERR("coap_new_client_session failed\n");
    return 0;
  }
  return 1;
}
/*---------------------------------------------------------------------------*/
static int
disclose(
#if WITH_TRAP && !WITH_IRAP
    uint8_t clients_fhmqv_mic[COAP_RAP_FHMQV_MIC_SIZE]
#endif /* WITH_TRAP && !WITH_IRAP */
    )
{
  coap_pdu_t *pdu = coap_pdu_init(COAP_MESSAGE_CON,
                                  COAP_REQUEST_CODE_PUT,
                                  coap_new_message_id(session),
                                  coap_opt_encode_size(COAP_OPTION_URI_PATH,
                                                       sizeof(disclose_uri)
                                                       - 1)
                                  + PAYLOAD_MARKER_SIZE
#if WITH_TRAP && !WITH_IRAP
                                  + COAP_RAP_FHMQV_MIC_SIZE
#endif /* WITH_TRAP && !WITH_IRAP */
                                  + sizeof(master_secret_to_share));
  if(!pdu) {
    LOG_ERR("coap_pdu_init failed\n");
    return 0;
  }
  if(!coap_add_option(pdu,
                      COAP_OPTION_URI_PATH,
                      sizeof(disclose_uri) - 1,
                      disclose_uri)) {
    LOG_ERR("coap_add_option failed\n");
    coap_delete_pdu(pdu);
    return 0;
  }
#if WITH_TRAP && !WITH_IRAP
  uint8_t *payload = coap_add_data_after(pdu,
                                         COAP_RAP_FHMQV_MIC_SIZE
                                         + sizeof(master_secret_to_share));
  if(!payload) {
    LOG_ERR("coap_add_data_after failed\n");
    coap_delete_pdu(pdu);
    return 0;
  }
  memcpy(payload, clients_fhmqv_mic, COAP_RAP_FHMQV_MIC_SIZE);
  memcpy(payload + COAP_RAP_FHMQV_MIC_SIZE,
         master_secret_to_share,
         sizeof(master_secret_to_share));
#else /* WITH_TRAP && !WITH_IRAP */
  if(!coap_add_data(pdu,
                    sizeof(master_secret_to_share),
                    master_secret_to_share)) {
    LOG_ERR("coap_add_data failed\n");
    coap_delete_pdu(pdu);
    return 0;
  }
#endif /* WITH_TRAP && !WITH_IRAP */
  return coap_send(session, pdu) != COAP_INVALID_MID;
}
/*---------------------------------------------------------------------------*/
static coap_response_t
on_disclose_response(coap_session_t *session,
                     const coap_pdu_t *sent,
                     const coap_pdu_t *received,
                     const coap_mid_t mid)
{
  LOG_INFO("on_disclose_response\n");
  process_poll(&filtering_client_process);
  return COAP_RESPONSE_OK;
}
/*---------------------------------------------------------------------------*/
void
filtering_client_start(void)
{
  list_init(subscription_list);
  process_start(&filtering_client_process, NULL);
}
/*---------------------------------------------------------------------------*/
void
filtering_client_subscribe(filtering_client_subscription_t *subscription)
{
  list_add(subscription_list, subscription);
}
/*---------------------------------------------------------------------------*/
static void
notify(void)
{
  for(filtering_client_subscription_t *subscription =
          list_head(subscription_list);
      subscription;
      subscription = list_item_next(subscription)) {
    subscription->on_registered(context);
  }
}
/*---------------------------------------------------------------------------*/
void
filtering_client_prolong(void)
{
  PROCESS_CONTEXT_BEGIN(&filtering_client_process);
  etimer_set(&update_timer, INACTIVITY_TIMEOUT * CLOCK_SECOND);
  PROCESS_CONTEXT_END(&filtering_client_process);
}
/*---------------------------------------------------------------------------*/
static int
send_update(void)
{
  coap_pdu_t *pdu = coap_pdu_init(COAP_MESSAGE_CON,
                                  COAP_REQUEST_CODE_GET,
                                  coap_new_message_id(session),
                                  coap_opt_encode_size(COAP_OPTION_URI_PATH,
                                                       sizeof(update_uri) - 1)
                                  + PAYLOAD_MARKER_SIZE);
  if(!pdu) {
    LOG_ERR("coap_pdu_init failed\n");
    return 0;
  }
  if(!coap_add_option(pdu,
                      COAP_OPTION_URI_PATH,
                      sizeof(update_uri) - 1,
                      update_uri)) {
    LOG_ERR("coap_add_option failed\n");
    coap_delete_pdu(pdu);
    return 0;
  }
  last_update_mid = coap_send(session, pdu);
  return last_update_mid != COAP_INVALID_MID;
}
/*---------------------------------------------------------------------------*/
static coap_response_t
on_response(coap_session_t *session,
            const coap_pdu_t *sent,
            const coap_pdu_t *received,
            const coap_mid_t mid)
{
  assert(mid != COAP_INVALID_MID);
  if(mid == last_update_mid) {
    LOG_INFO("on_update_response\n");
    filtering_client_prolong();
    process_poll(&filtering_client_process);
    return COAP_RESPONSE_OK;
  }
#ifdef AGGREGATOR
  if(mid == last_otp_mid) {
    if(!is_connected) {
      LOG_ERR("on_otp_response while not being connected\n");
      return COAP_RESPONSE_OK;
    }
    if(ctimer_expired(&otp_timeout)) {
      LOG_ERR("late OTP response - we might need to extend our timeout\n");
      return COAP_RESPONSE_OK;
    }

    size_t payload_len;
    const uint8_t *payload;
    coap_get_data(received, &payload_len, &payload);
    if(payload_len != CSL_FRAMER_POTR_OTP_LEN) {
      LOG_ERR("OTP has unexpected length\n");
      ctimer_stop(&otp_timeout);
      on_got_otp_result(NULL);
      return COAP_RESPONSE_FAIL;
    }
    got_filtering_otp = true;
    memcpy(filtering_otp, payload, CSL_FRAMER_POTR_OTP_LEN);
    filtering_client_prolong();
    ctimer_stop(&otp_timeout);
    on_got_otp_result(NULL);
    return COAP_RESPONSE_OK;
  }
#endif /* AGGREGATOR */
  /*
   * TODO dispatch other responses to applications
   * TODO maybe use separate tokens for each application to ease dispatching
   */
  return COAP_RESPONSE_FAIL;
}
/*---------------------------------------------------------------------------*/
static void
on_timeout(coap_session_t *session,
           const coap_pdu_t *sent,
           const coap_nack_reason_t reason,
           const coap_mid_t mid)
{
  LOG_ERR("on_timeout\n");
  timeout_flag = true;
  process_poll(&filtering_client_process);
}
/*---------------------------------------------------------------------------*/
#ifdef AGGREGATOR
struct pt *
filtering_client_get_otp_retrieval_protothread(void)
{
  return is_connected && !timeout_flag ? &pt : NULL;
}
/*---------------------------------------------------------------------------*/
PT_THREAD(filtering_client_retrieve_filtering_otp(bool *successful))
{
  PT_BEGIN(&pt);

  assert(ctimer_expired(&otp_timeout));
  coap_pdu_t *pdu = coap_pdu_init(COAP_MESSAGE_NON,
                                  COAP_REQUEST_CODE_GET,
                                  coap_new_message_id(session),
                                  coap_opt_encode_size(COAP_OPTION_URI_PATH,
                                                       sizeof(otp_uri) - 1)
                                  + PAYLOAD_MARKER_SIZE
                                  + OTP_PAYLOAD_SIZE);
  if(!pdu) {
    LOG_ERR("coap_pdu_init failed\n");
    *successful = false;
    PT_EXIT(&pt);
  }
  if(!coap_add_option(pdu,
                      COAP_OPTION_URI_PATH,
                      sizeof(otp_uri) - 1,
                      otp_uri)) {
    LOG_ERR("coap_add_option failed\n");
    coap_delete_pdu(pdu);
    *successful = false;
    PT_EXIT(&pt);
  }
  uint8_t *payload = coap_add_data_after(pdu, OTP_PAYLOAD_SIZE);
  if(!payload) {
    LOG_ERR("coap_add_data_after failed\n");
    coap_delete_pdu(pdu);
    *successful = false;
    PT_EXIT(&pt);
  }
  *payload = packetbuf_totlen()
             | ((packetbuf_attr(PACKETBUF_ATTR_INBOUND_OSCORE)
                 == UIPBUF_ATTR_FLAGS_INBOUND_OSCORE_REQUEST)
                ? RELATES_TO_REQUEST_FLAG
                : 0);
  payload++;
  wake_up_counter_write(payload, csl_predict_wake_up_counter());
  payload += WAKE_UP_COUNTER_LEN;
  linkaddr_write(payload, packetbuf_addr(PACKETBUF_ADDR_RECEIVER));
  payload += LINKADDR_SIZE;
  uint16_t mid = LLSEC802154_HTONS(
                     packetbuf_attr(PACKETBUF_ATTR_COAP_MESSAGE_ID));
  *payload++ = mid;
  *payload++ = mid >> 8;
  last_otp_mid = coap_send(session, pdu);
  if(last_otp_mid == COAP_INVALID_MID) {
    LOG_ERR("coap_send failed\n");
    *successful = false;
    PT_EXIT(&pt);
  }
  ctimer_set(&otp_timeout,
             CLOCK_SECOND / (1000 / AGGREGATOR_OTP_WAIT_TIME),
             on_got_otp_result,
             NULL);
  process_to_notify = process_current;
  got_filtering_otp = false;
  got_result = false;
  PT_WAIT_UNTIL(&pt, got_result);
  *successful = got_filtering_otp;
  if(timeout_flag) {
    process_poll(&filtering_client_process);
  }

  PT_END(&pt);
}
/*---------------------------------------------------------------------------*/
static void
on_got_otp_result(void *ptr)
{
  got_result = true;
  process_poll(process_to_notify);
}
/*---------------------------------------------------------------------------*/
void
filtering_client_get_filtering_otp(uint8_t dst[CSL_FRAMER_POTR_OTP_LEN])
{
  memcpy(dst, filtering_otp, CSL_FRAMER_POTR_OTP_LEN);
}
/*---------------------------------------------------------------------------*/
#else /* AGGREGATOR */
bool
filtering_client_set_otp_key(void)
{
  if(!can_set_otp_key) {
    return false;
  }
#if WITH_CC_OPTIMIZATION
  cc_aes_128_active_key_area = OTP_KEY_AREA;
  return true;
#else /* WITH_CC_OPTIMIZATION */
  return CCM_STAR.set_key(otp_key);
#endif /* WITH_CC_OPTIMIZATION */
}
/*---------------------------------------------------------------------------*/
bool
filtering_client_unset_otp_key(void)
{
#if WITH_CC_OPTIMIZATION
  cc_aes_128_active_key_area = CC_AES_128_KEY_AREA;
  return true;
#else /* WITH_CC_OPTIMIZATION */
  return false;
#endif /* WITH_CC_OPTIMIZATION */
}
#endif /* AGGREGATOR */
/*---------------------------------------------------------------------------*/

/** @} */
