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
 * \addtogroup filtering
 * @{
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
#include "lib/ecc.h"
#include "lib/sha-256.h"
#include "net/ipv6/uip-ds6.h"
#include "net/linkaddr.h"
#include "net/routing/routing.h"
#include "net/mac/csl/csl.h"
#include "net/mac/wake-up-counter.h"
#include "net/packetbuf.h"
#include <string.h>

#define WITH_CC2538_OPTIMIZATION \
  (CONTIKI_TARGET_CC2538DK || CONTIKI_TARGET_OPENMOTE || CONTIKI_TARGET_ZOUL)
#if WITH_CC2538_OPTIMIZATION
#define OTP_KEY_AREA (1)
#include "dev/cc2538-aes-128.h"
#endif /* WITH_CC2538_OPTIMIZATION */

/* Log configuration */
#include "sys/log.h"
#define LOG_MODULE "Filtering"
#define LOG_LEVEL LOG_LEVEL_COAP

#ifdef FILTERING_CLIENT_CONF_WITH_TRAP
#define WITH_TRAP FILTERING_CLIENT_CONF_WITH_TRAP
#else /* FILTERING_CLIENT_CONF_WITH_TRAP */
#define WITH_TRAP 1
#endif /* FILTERING_CLIENT_CONF_WITH_TRAP */

#define MAX_COOKIE_SIZE (SHA_256_DIGEST_LENGTH / 4)
#define PADDING_SIZE (MAX_COOKIE_SIZE)
#define INACTIVITY_TIMEOUT (60 * 5) /* seconds */
#define ID_CONTEXT_SIZE (8)
#define PAYLOAD_MARKER_SIZE (1)
#define ECC_CURVE_SIZE (ECC_CURVE_P_256_SIZE)
#define ECC_SIGNATURE_SIZE (ECC_CURVE_SIZE * 2)
#define FHMQV_MIC_LEN (8)

/* these definitions are for creating /otp requests */
#define RELATES_TO_REQUEST_FLAG (1 << 7)
#define OTP_PAYLOAD_SIZE (1 + WAKE_UP_COUNTER_LEN + LINKADDR_SIZE + 2)

#define MAX_ATTESTATION_REPORT_SIZE \
  (1 /* compression information */ \
   + ECC_CURVE_SIZE /* SM's public key */ \
   + ECC_SIGNATURE_SIZE /* signature of SM report */ \
   + ECC_CURVE_SIZE /* TEE's ephemeral public key */ \
   + (WITH_TRAP \
  ? FHMQV_MIC_LEN /* truncated FHMQV MIC */ \
  : ECC_SIGNATURE_SIZE /* signature of TEE report */))

static const uint8_t master_secret_to_share[AES_128_KEY_LENGTH] = {
  0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7,
  0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF
};
static const uint8_t our_private_key[ECC_CURVE_SIZE] = {
  0xf0, 0x08, 0x8f, 0x07, 0x6b, 0xda, 0xd0, 0x06,
  0x22, 0x39, 0xa8, 0x0d, 0x28, 0x6c, 0xfc, 0xb5,
  0xac, 0x9d, 0x95, 0x74, 0x27, 0xf6, 0x01, 0x81,
  0x5e, 0xe2, 0x10, 0x09, 0xbc, 0x47, 0x9b, 0x85
};
#if WITH_TRAP
static const uint8_t our_public_key[ECC_CURVE_SIZE * 2] = {
  0x01, 0xb8, 0x07, 0x0e, 0x9a, 0xd9, 0xb7, 0x56,
  0xa8, 0x30, 0xa2, 0xab, 0xc4, 0xbf, 0xb2, 0xb6,
  0x0c, 0x25, 0xa3, 0xdd, 0x41, 0x52, 0x85, 0x6d,
  0xdc, 0xab, 0x16, 0x08, 0x17, 0xf4, 0x46, 0xe6,
  0xb7, 0x36, 0xeb, 0xc7, 0x91, 0xcd, 0xa0, 0x18,
  0x30, 0x48, 0x3d, 0x7f, 0xc1, 0x46, 0xf5, 0x61,
  0xf1, 0x68, 0x4a, 0xd8, 0x73, 0x4f, 0xf1, 0xc2,
  0xe4, 0x9c, 0xcc, 0x32, 0x3c, 0x4e, 0x48, 0x55
};
#endif /* WITH_TRAP */

static const uint8_t root_of_trusts_public_key[ECC_CURVE_SIZE * 2] = {
  0x79, 0x83, 0xca, 0x61, 0x64, 0xd4, 0x1c, 0x2b,
  0x0d, 0x0c, 0x98, 0x2b, 0x15, 0x41, 0x0f, 0xba,
  0xa0, 0x32, 0xcb, 0x1a, 0x84, 0x00, 0x10, 0x7f,
  0x3b, 0xa8, 0xa2, 0x15, 0x16, 0x8c, 0x1b, 0x92,
  0x72, 0x1c, 0xe5, 0xbe, 0x22, 0x68, 0xd1, 0xb7,
  0x95, 0x8b, 0x8a, 0xee, 0x90, 0x65, 0xbb, 0x0c,
  0x5d, 0x31, 0xf9, 0x72, 0xd1, 0x6f, 0x58, 0x43,
  0xb6, 0x34, 0xe7, 0x6a, 0xb4, 0xf0, 0x8f, 0xd3,
};
static const uint8_t expected_sm_hash[SHA_256_DIGEST_LENGTH] = {
  0xb1, 0x63, 0xea, 0x85, 0x92, 0x1e, 0xef, 0x2d,
  0xf7, 0xcb, 0x15, 0x69, 0x8f, 0x1a, 0xa6, 0x2c,
  0xe1, 0xe8, 0x6a, 0x35, 0x46, 0x36, 0xf3, 0x03,
  0x55, 0xd4, 0x1f, 0x64, 0x68, 0xb3, 0x60, 0x49,
};
static const uint8_t expected_tee_hash[SHA_256_DIGEST_LENGTH] = {
  0x3f, 0xff, 0xe7, 0x66, 0xd6, 0x45, 0xb8, 0x0d,
  0xb6, 0xed, 0x67, 0xe0, 0x6a, 0x59, 0x3f, 0xa3,
  0x96, 0xbc, 0x4c, 0xb9, 0x28, 0xca, 0xad, 0x55,
  0xb9, 0x61, 0xcd, 0x4f, 0xb2, 0x7c, 0x9b, 0x60,
};

static int init_context(void);
static void clean_up(void);
static PT_THREAD(generate_ephemeral_key_pair(int *result));
static int init_libcoap(void);
static int knock(void);
static coap_response_t on_cookie(coap_session_t *session,
                                 const coap_pdu_t *sent,
                                 const coap_pdu_t *received,
                                 const coap_mid_t mid);
static PT_THREAD(initiate_registration(int *result));
static coap_response_t on_report(coap_session_t *session,
                                 const coap_pdu_t *sent,
                                 const coap_pdu_t *received,
                                 const coap_mid_t mid);
static PT_THREAD(verify_sm_report(int *result));
static PT_THREAD(verify_tee_report(
                   oscore_ng_id_context_t *id_context,
#if WITH_TRAP
                   uint8_t clients_fhmqv_mic[static FHMQV_MIC_LEN],
#endif /* WITH_TRAP */
                   int *result));
static int disclose(
#if WITH_TRAP
  uint8_t clients_fhmqv_mic[FHMQV_MIC_LEN]
#endif /* WITH_TRAP */
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
static const uint8_t knock_uri[] = "kno";
static const uint8_t register_uri[] = "reg";
static const uint8_t disclose_uri[] = "dis";
static const uint8_t update_uri[] = "upd";
#ifdef AGGREGATOR
static const uint8_t otp_uri[] = "otp";
#endif /* AGGREGATOR */
static struct pt pt;
LIST(subscription_list);
static bool timeout_flag;
static coap_context_t *context;
static coap_session_t *session;
static bool is_connected;
static bool can_set_otp_key;
PROCESS(filtering_client_process, "filtering_client_process");
static union {
  struct etimer periodic_timer;
  struct {
    uint8_t our_ephemeral_private_key[ECC_CURVE_SIZE];
#if WITH_TRAP
    uint8_t our_ephemeral_public_key[ECC_CURVE_SIZE * 2];
    union {
      uint8_t tees_ephemeral_public_key[ECC_CURVE_SIZE * 2];
      uint8_t tees_ephemeral_public_key_compressed[1 + ECC_CURVE_SIZE];
    };
    union {
      uint8_t sms_public_key[ECC_CURVE_SIZE * 2];
      uint8_t sms_public_key_compressed[1 + ECC_CURVE_SIZE];
    };
#else /* WITH_TRAP */
    uint8_t our_ephemeral_public_key_compressed[1 + ECC_CURVE_SIZE];
    uint8_t tees_ephemeral_public_key_compressed[1 + ECC_CURVE_SIZE];
    uint8_t sms_public_key_compressed[1 + ECC_CURVE_SIZE];
#endif /* WITH_TRAP */
    union {
      struct {
        uint8_t cookie[MAX_COOKIE_SIZE];
        size_t cookie_size;
      };
      struct {
        uint8_t bootloaders_signature[ECC_SIGNATURE_SIZE];
#if WITH_TRAP
        uint8_t tees_fhmqv_mic[FHMQV_MIC_LEN];
#else /* WITH_TRAP */
        uint8_t sms_signature[ECC_SIGNATURE_SIZE];
#endif /* WITH_TRAP */
      };
    };
  } attestation;
  struct {
    coap_oscore_ng_keying_material_t km;
    union {
      struct {
        uint8_t oscore_ng_key[AES_128_KEY_LENGTH];
        uint8_t otp_key[AES_128_KEY_LENGTH];
      };
      uint8_t okm[2 * AES_128_KEY_LENGTH];
    } keys;
    struct etimer update_timer;
    coap_mid_t last_update_mid;
#ifdef AGGREGATOR
    bool got_result;
    bool got_filtering_otp;
    struct process *process_to_notify;
    uint8_t filtering_otp[CSL_FRAMER_POTR_OTP_LEN];
    struct ctimer otp_timeout;
    coap_mid_t last_otp_mid;
#endif /* AGGREGATOR */
  } session;
} heap;

/*---------------------------------------------------------------------------*/
static const coap_oscore_ng_keying_material_t *
get_keying_material(const coap_bin_const_t *recipient_id)
{
  return coap_binary_equal(recipient_id, &middlebox_id)
      ? &heap.session.km
      : NULL;
}
/*---------------------------------------------------------------------------*/
PROCESS_THREAD(filtering_client_process, ev, data)
{
  int result;

  PROCESS_BEGIN();

  if(!init_context()) {
    LOG_ERR("init_context failed\n");
    PROCESS_EXIT();
  }

  while(1) {
    clean_up();

    /* wait for an IPv6 address */
    while(!NETSTACK_ROUTING.node_is_reachable()) {
      etimer_set(&heap.periodic_timer, 5 * CLOCK_SECOND);
      PROCESS_WAIT_UNTIL(etimer_expired(&heap.periodic_timer));
      LOG_INFO("Not reachable yet\n");
    }
    LOG_INFO("Became reachable\n");

    ECC.enable(&ecc_curve_p_256);

    PROCESS_PT_SPAWN(&pt, generate_ephemeral_key_pair(&result));
    if(result) {
      LOG_ERR("generate_ephemeral_key_pair failed\n");
      continue;
    }

    if(!init_libcoap()) {
      continue;
    }

    /* kno request */
    if(!knock()) {
      LOG_ERR("knock failed\n");
      continue;
    }
    PROCESS_YIELD_UNTIL(ev == PROCESS_EVENT_POLL);
    if(timeout_flag) {
      continue;
    }

    /* reg request */
    PROCESS_PT_SPAWN(&pt, initiate_registration(&result));
    if(result) {
      LOG_ERR("initiate_registration failed\n");
      continue;
    }
    PROCESS_YIELD_UNTIL(ev == PROCESS_EVENT_POLL);
    if(timeout_flag) {
      continue;
    }

    PROCESS_PT_SPAWN(&pt, verify_sm_report(&result));
    if(result) {
      LOG_ERR("received invalid SM report\n");
      continue;
    }

    /* verify TEE report */
    oscore_ng_id_context_t id_context;
#if WITH_TRAP
    uint8_t clients_fhmqv_mic[FHMQV_MIC_LEN];
#endif /* WITH_TRAP */
    PROCESS_PT_SPAWN(&pt,
                     verify_tee_report(&id_context,
#if WITH_TRAP
                                       clients_fhmqv_mic,
#endif /* WITH_TRAP */
                                       &result));
    if(result) {
      LOG_ERR("received invalid TEE report\n");
      continue;
    }

    ECC.disable();

    /* init OSCORE-NG session */
    oscore_ng_init_keying_material(&heap.session.km,
                                   heap.session.keys.oscore_ng_key,
                                   AES_128_KEY_LENGTH,
                                   NULL,
                                   0);
    if(!coap_oscore_ng_init_client_session(session, &middlebox_id, 0)) {
      LOG_ERR("coap_oscore_ng_init_client_session failed\n");
      continue;
    }

    /*
     * Disclose messages contain the full ID Context in the kid context
     * field. This allows the middlebox to look up the right registration.
     */
    oscore_ng_set_id_context(session->oscore_ng_context, &id_context, true);

    /* share secrets */
#if WITH_CC2538_OPTIMIZATION
    /* store the OTP key in the key store for immediate access */
    while(!AES_128.get_lock());
    cc2538_aes_128_active_key_area = OTP_KEY_AREA;
    can_set_otp_key = AES_128.set_key(heap.session.keys.otp_key);
    cc2538_aes_128_active_key_area = CC2538_AES_128_KEY_AREA;
    AES_128.release_lock();
    if(!can_set_otp_key) {
      LOG_ERR("set_key failed\n");
      assert(false);
      continue;
    }
#else /* WITH_CC2538_OPTIMIZATION */
    can_set_otp_key = true;
#endif /* WITH_CC2538_OPTIMIZATION */
    if(!disclose(
#if WITH_TRAP
         clients_fhmqv_mic
#endif /* WITH_TRAP */
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
    heap.session.last_otp_mid = COAP_INVALID_MID;
    ctimer_stop(&heap.session.otp_timeout);
#endif /* AGGREGATOR */
    /* notify observers of successful remote attestation */
    is_connected = true;
    notify();

    /* send updates in the absence of messages from the middlebox */
    coap_register_response_handler(context, on_response);
    heap.session.last_update_mid = COAP_INVALID_MID;
    filtering_client_prolong();
    while(1) {
      PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&heap.session.update_timer));
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
    PROCESS_WAIT_UNTIL(ctimer_expired(&heap.session.otp_timeout));
#endif /* AGGREGATOR */
    is_connected = false;
  }

  PROCESS_END();
}
/*---------------------------------------------------------------------------*/
static int
init_context(void)
{
  context = coap_new_context(NULL);
  if(!context) {
    LOG_ERR("coap_new_context failed\n");
    return 0;
  }
  coap_register_nack_handler(context, on_timeout);
  coap_bin_const_t my_id = {
    .length = LINKADDR_SIZE,
    .s = linkaddr_node_addr.u8
  };
  return coap_oscore_ng_init(context, get_keying_material, &my_id);
}
/*---------------------------------------------------------------------------*/
static void
clean_up(void)
{
  ECC.disable();
  coap_session_release(session);
  session = NULL;
  can_set_otp_key = false;
}
/*---------------------------------------------------------------------------*/
static PT_THREAD(generate_ephemeral_key_pair(int *result))
{
  PT_BEGIN(&pt);

#if !WITH_TRAP
  uint8_t our_ephemeral_public_key[ECC_CURVE_SIZE * 2];
#endif /* !WITH_TRAP */

  PT_SPAWN(&pt,
           ECC.get_protothread(),
           ECC.generate_key_pair(heap.attestation.our_ephemeral_private_key,
#if WITH_TRAP
                                 heap.attestation.our_ephemeral_public_key,
#else /* WITH_TRAP */
                                 our_ephemeral_public_key,
#endif /* WITH_TRAP */
                                 result));
#if !WITH_TRAP
  if(*result) {
    LOG_ERR("ECC.generate_key_pair failed\n");
    PT_EXIT(&pt);
  }
  ECC.compress_public_key(
    our_ephemeral_public_key,
    heap.attestation.our_ephemeral_public_key_compressed);
#endif /* !WITH_TRAP */

  PT_END(&pt);
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
  timeout_flag = false;
  return 1;
}
/*---------------------------------------------------------------------------*/
static int
knock(void)
{
  coap_register_response_handler(context, on_cookie);
  coap_pdu_t *pdu = coap_pdu_init(COAP_MESSAGE_CON,
                                  COAP_REQUEST_CODE_GET,
                                  coap_new_message_id(session),
                                  coap_opt_encode_size(COAP_OPTION_URI_PATH,
                                                       sizeof(knock_uri) - 1)
                                  + PAYLOAD_MARKER_SIZE
                                  + PADDING_SIZE);
  if(!pdu) {
    LOG_ERR("coap_pdu_init failed\n");
    return 0;
  }
  if(!coap_add_option(pdu, COAP_OPTION_URI_PATH,
                      sizeof(knock_uri) - 1, knock_uri)) {
    LOG_ERR("coap_add_option failed\n");
    coap_delete_pdu(pdu);
    return 0;
  }
  uint8_t *payload = coap_add_data_after(pdu, PADDING_SIZE);
  if(!payload) {
    LOG_ERR("coap_add_data_after failed\n");
    coap_delete_pdu(pdu);
    return 0;
  }
  memset(payload, 0, PADDING_SIZE);
  return coap_send(session, pdu) != COAP_INVALID_MID;
}
/*---------------------------------------------------------------------------*/
static coap_response_t
on_cookie(coap_session_t *session,
          const coap_pdu_t *sent,
          const coap_pdu_t *received,
          const coap_mid_t mid)
{
  const uint8_t *payload_ptr;
  coap_get_data(received, &heap.attestation.cookie_size, &payload_ptr);
  if(heap.attestation.cookie_size > MAX_COOKIE_SIZE) {
    LOG_ERR("cookie is too large\n");
    timeout_flag = true; /* TODO adapt libcoap to continue retransmitting */
    process_poll(&filtering_client_process);
    return COAP_RESPONSE_FAIL;
  }
  memcpy(heap.attestation.cookie, payload_ptr, heap.attestation.cookie_size);
  process_poll(&filtering_client_process);
  return COAP_RESPONSE_OK;
}
/*---------------------------------------------------------------------------*/
static PT_THREAD(initiate_registration(int *result))
{
  PT_BEGIN(&pt);

#if !WITH_TRAP
  uint8_t signature[ECC_SIGNATURE_SIZE];

  /* sign our compressed ephemeral public key */
  {
    uint8_t hash[SHA_256_DIGEST_LENGTH];
    SHA_256.hash(heap.attestation.our_ephemeral_public_key_compressed,
                 sizeof(heap.attestation.our_ephemeral_public_key_compressed),
                 hash);
    PT_SPAWN(&pt,
             ECC.get_protothread(),
             ECC.sign(signature, hash, our_private_key, result));
  }
  if(*result) {
    LOG_ERR("ECC.sign failed with error %u\n", *result);
    PT_EXIT(&pt);
  }
#endif /* !WITH_TRAP */

  {
    coap_pdu_t *pdu = coap_pdu_init(
      COAP_MESSAGE_CON,
      COAP_REQUEST_CODE_GET,
      coap_new_message_id(session),
      coap_opt_encode_size(COAP_OPTION_URI_PATH,
                           sizeof(register_uri) - 1)
      + PAYLOAD_MARKER_SIZE
      + (1 + ECC_CURVE_SIZE)
      + (WITH_TRAP ? 0 : ECC_SIGNATURE_SIZE)
      + heap.attestation.cookie_size);
    if(!pdu) {
      LOG_ERR("coap_pdu_init failed\n");
      *result = 1;
      PT_EXIT(&pt);
    }
    if(!coap_add_option(pdu,
                        COAP_OPTION_URI_PATH,
                        sizeof(register_uri) - 1,
                        register_uri)) {
      LOG_ERR("coap_add_option failed\n");
      coap_delete_pdu(pdu);
      *result = 1;
      PT_EXIT(&pt);
    }
    uint8_t *pdu_data = coap_add_data_after(
      pdu,
      (1 + ECC_CURVE_SIZE)
      + (WITH_TRAP ? 0 : ECC_SIGNATURE_SIZE)
      + heap.attestation.cookie_size);
    if(!pdu_data) {
      LOG_ERR("coap_add_data_after failed\n");
      coap_delete_pdu(pdu);
      *result = 1;
      PT_EXIT(&pt);
    }
#if WITH_TRAP
    ECC.compress_public_key(heap.attestation.our_ephemeral_public_key,
                            pdu_data);
    pdu_data += 1 + ECC_CURVE_SIZE;
#else /* WITH_TRAP */
    memcpy(pdu_data,
           heap.attestation.our_ephemeral_public_key_compressed,
           sizeof(heap.attestation.our_ephemeral_public_key_compressed));
    pdu_data += 1 + ECC_CURVE_SIZE;
    memcpy(pdu_data, signature, sizeof(signature));
    pdu_data += sizeof(signature);
#endif /* WITH_TRAP */
    memcpy(pdu_data, heap.attestation.cookie, heap.attestation.cookie_size);
    coap_register_response_handler(context, on_report);
    *result = coap_send(session, pdu) == COAP_INVALID_MID;
  }

  PT_END(&pt);
}
/*---------------------------------------------------------------------------*/
static coap_response_t
on_report(coap_session_t *session,
          const coap_pdu_t *sent,
          const coap_pdu_t *received,
          const coap_mid_t mid)
{
  size_t payload_len;
  const uint8_t *payload_ptr;
  coap_get_data(received, &payload_len, &payload_ptr);

  /* validate length */
  if(payload_len != MAX_ATTESTATION_REPORT_SIZE) {
    LOG_ERR("The attestation report has an invalid length %zu != %u\n",
            payload_len,
            MAX_ATTESTATION_REPORT_SIZE);
    goto error;
  }

  /* parse */
  heap.attestation.sms_public_key_compressed[0] =
    2 | (*payload_ptr & 1);
  heap.attestation.tees_ephemeral_public_key_compressed[0] =
    2 | ((*payload_ptr & 2) >> 1);
  payload_ptr++;
  memcpy(heap.attestation.sms_public_key_compressed + 1,
         payload_ptr,
         ECC_CURVE_SIZE);
  payload_ptr += ECC_CURVE_SIZE;
  memcpy(heap.attestation.bootloaders_signature,
         payload_ptr,
         sizeof(heap.attestation.bootloaders_signature));
  payload_ptr += sizeof(heap.attestation.bootloaders_signature);
  memcpy(
    heap.attestation.tees_ephemeral_public_key_compressed + 1,
    payload_ptr,
    ECC_CURVE_SIZE);
  payload_ptr += ECC_CURVE_SIZE;
#if WITH_TRAP
  memcpy(heap.attestation.tees_fhmqv_mic,
         payload_ptr,
         sizeof(heap.attestation.tees_fhmqv_mic));
#else /* WITH_TRAP */
  memcpy(heap.attestation.sms_signature,
         payload_ptr,
         sizeof(heap.attestation.sms_signature));
#endif /* WITH_TRAP */

  process_poll(&filtering_client_process);
  return COAP_RESPONSE_OK;
error:
  timeout_flag = true; /* TODO adapt libcoap to continue retransmitting */
  process_poll(&filtering_client_process);
  return COAP_RESPONSE_FAIL;
}
/*---------------------------------------------------------------------------*/
static PT_THREAD(verify_sm_report(int *result))
{
  uint8_t sm_report_hash[SHA_256_DIGEST_LENGTH];

  PT_BEGIN(&pt);

  SHA_256.init();
  SHA_256.update(expected_sm_hash, sizeof(expected_sm_hash));
  SHA_256.update(heap.attestation.sms_public_key_compressed,
                 sizeof(heap.attestation.sms_public_key_compressed));
  SHA_256.finalize(sm_report_hash);
  PT_SPAWN(&pt,
           ECC.get_protothread(),
           ECC.verify(heap.attestation.bootloaders_signature,
                      sm_report_hash,
                      root_of_trusts_public_key,
                      result));

  PT_END(&pt);
}
/*---------------------------------------------------------------------------*/
static PT_THREAD(verify_tee_report(
                   oscore_ng_id_context_t *id_context,
#if WITH_TRAP
                   uint8_t clients_fhmqv_mic[static FHMQV_MIC_LEN],
#endif /* WITH_TRAP */
                   int *result))
{
#if !WITH_TRAP
  uint8_t sms_public_key[ECC_CURVE_SIZE * 2];
#endif /* !WITH_TRAP */

  PT_BEGIN(&pt);

#if WITH_TRAP
  /* decompress TEE's ephemeral public key */
  PT_SPAWN(
    &pt,
    ECC.get_protothread(),
    ECC.decompress_public_key(
      heap.attestation.tees_ephemeral_public_key,
      heap.attestation.tees_ephemeral_public_key_compressed,
      result));
  if(*result) {
    LOG_ERR("decompression of TEE's ephemeral public key failed\n");
    PT_EXIT(&pt);
  }
  PT_SPAWN(&pt,
           ECC.get_protothread(),
           ECC.validate_public_key(
             heap.attestation.tees_ephemeral_public_key,
             result));
  if(*result) {
    LOG_ERR("validation of TEE's ephemeral public key failed\n");
    PT_EXIT(&pt);
  }
#endif /* WITH_TRAP */

  /* decompress SM's public key */
  PT_SPAWN(&pt,
           ECC.get_protothread(),
           ECC.decompress_public_key(
#if WITH_TRAP
             heap.attestation.sms_public_key,
#else /* WITH_TRAP */
             sms_public_key,
#endif /* WITH_TRAP */
             heap.attestation.sms_public_key_compressed,
             result));
  if(*result) {
    LOG_ERR("decompression of SM's public key failed\n");
    PT_EXIT(&pt);
  }

#if WITH_TRAP
  union {
    struct {
      uint8_t d[SHA_256_DIGEST_LENGTH];
      uint8_t e[SHA_256_DIGEST_LENGTH];
    };
    struct {
      uint8_t sigma[ECC_CURVE_SIZE];
      uint8_t ikm[ECC_CURVE_SIZE * 8];
    };
    struct {
      uint8_t okm[ECC_CURVE_SIZE * 2];
      uint8_t fhmqv_mic[SHA_256_DIGEST_LENGTH];
    };
  } stack;

  SHA_256.init();
  SHA_256.update(heap.attestation.our_ephemeral_public_key,
                 sizeof(heap.attestation.our_ephemeral_public_key));
  SHA_256.update(heap.attestation.tees_ephemeral_public_key,
                 sizeof(heap.attestation.tees_ephemeral_public_key));
  SHA_256.update(our_public_key,
                 sizeof(our_public_key));
  SHA_256.update(heap.attestation.sms_public_key,
                 sizeof(heap.attestation.sms_public_key));
  SHA_256.finalize(stack.d);
  memcpy(stack.e + (sizeof(stack.e) / 2), stack.d, sizeof(stack.d) / 2);
  memset(stack.e, 0, sizeof(stack.e) / 2);
  memset(stack.d, 0, sizeof(stack.d) / 2);
  PT_SPAWN(&pt,
           ECC.get_protothread(),
           ECC.generate_fhmqv_secret(
             stack.sigma,
             our_private_key,
             heap.attestation.our_ephemeral_private_key,
             heap.attestation.sms_public_key,
             heap.attestation.tees_ephemeral_public_key,
             stack.d,
             stack.e,
             result));
  if(*result) {
    LOG_ERR("ECC.generate_fhmqv_secret failed\n");
    PT_EXIT(&pt);
  }
  memcpy(stack.ikm,
         our_public_key,
         sizeof(our_public_key));
  memcpy(stack.ikm + 2 * ECC_CURVE_SIZE,
         heap.attestation.sms_public_key,
         sizeof(heap.attestation.sms_public_key));
  memcpy(stack.ikm + 4 * ECC_CURVE_SIZE,
         heap.attestation.our_ephemeral_public_key,
         sizeof(heap.attestation.our_ephemeral_public_key));
  memcpy(stack.ikm + 6 * ECC_CURVE_SIZE,
         heap.attestation.tees_ephemeral_public_key,
         sizeof(heap.attestation.tees_ephemeral_public_key));
  sha_256_hkdf(NULL, 0, /* TODO use salt */
               stack.sigma, sizeof(stack.sigma),
               stack.ikm, sizeof(stack.ikm),
               stack.okm, sizeof(stack.okm));

  sha_256_hmac_init(stack.okm, ECC_CURVE_SIZE);
  sha_256_hmac_update(heap.attestation.sms_public_key,
                      sizeof(heap.attestation.sms_public_key));
  sha_256_hmac_update(heap.attestation.tees_ephemeral_public_key,
                      sizeof(heap.attestation.tees_ephemeral_public_key));
  sha_256_hmac_update(expected_tee_hash, sizeof(expected_tee_hash));
  sha_256_hmac_finish(stack.fhmqv_mic);
  if(memcmp(heap.attestation.tees_fhmqv_mic,
            stack.fhmqv_mic,
            sizeof(heap.attestation.tees_fhmqv_mic))) {
    LOG_ERR("received invalid TEE report\n");
    *result = 1;
    PT_EXIT(&pt);
  }

  sha_256_hmac_init(stack.okm, ECC_CURVE_SIZE);
  sha_256_hmac_update(our_public_key,
                      sizeof(our_public_key));
  sha_256_hmac_update(heap.attestation.our_ephemeral_public_key,
                      sizeof(heap.attestation.our_ephemeral_public_key));
  sha_256_hmac_finish(stack.fhmqv_mic);
  memcpy(clients_fhmqv_mic, stack.fhmqv_mic, FHMQV_MIC_LEN);

  id_context->len = ID_CONTEXT_SIZE;
  memcpy(id_context->u8,
         heap.attestation.our_ephemeral_public_key,
         ID_CONTEXT_SIZE);
  memcpy(heap.session.keys.okm,
         stack.okm + ECC_CURVE_SIZE,
         sizeof(heap.session.keys.okm));
#else /* WITH_TRAP */
  union {
    uint8_t tee_report_hash[SHA_256_DIGEST_LENGTH];
    uint8_t tees_ephemeral_public_key[ECC_CURVE_SIZE * 2];
    uint8_t shared_secret[ECC_CURVE_SIZE];
  } stack;

  /* verify TEE report */
  SHA_256.init();
  SHA_256.update(expected_tee_hash, SHA_256_DIGEST_LENGTH);
  SHA_256.update(
    heap.attestation.our_ephemeral_public_key_compressed,
    sizeof(heap.attestation.our_ephemeral_public_key_compressed));
  SHA_256.update(
    heap.attestation.tees_ephemeral_public_key_compressed,
    sizeof(heap.attestation.tees_ephemeral_public_key_compressed));
  SHA_256.finalize(stack.tee_report_hash);
  PT_SPAWN(&pt,
           ECC.get_protothread(),
           ECC.verify(heap.attestation.sms_signature,
                      stack.tee_report_hash,
                      sms_public_key,
                      result));
  if(*result) {
    LOG_ERR("received invalid TEE report\n");
    PT_EXIT(&pt);
  }

  /* decompress TEE's ephemeral public key */
  PT_SPAWN(
    &pt,
    ECC.get_protothread(),
    ECC.decompress_public_key(
      stack.tees_ephemeral_public_key,
      heap.attestation.tees_ephemeral_public_key_compressed,
      result));
  if(*result) {
    LOG_ERR("decompression of TEE's ephemeral public key failed\n");
    PT_EXIT(&pt);
  }

  /* generate shared secret */
  PT_SPAWN(&pt,
           ECC.get_protothread(),
           ECC.generate_shared_secret(
             stack.shared_secret,
             heap.attestation.our_ephemeral_private_key,
             stack.tees_ephemeral_public_key,
             result));
  if(*result) {
    LOG_ERR("ECC.generate_shared_secret failed due to %u\n", *result);
    PT_EXIT(&pt);
  }

  /* derive K_OSCORE and K_OTP */
  memcpy(id_context->u8,
         heap.attestation.our_ephemeral_public_key_compressed + 1,
         ID_CONTEXT_SIZE);
  sha_256_hkdf(heap.attestation.our_ephemeral_public_key_compressed,
               sizeof(heap.attestation.our_ephemeral_public_key_compressed),
               stack.shared_secret, sizeof(stack.shared_secret),
               NULL, 0,
               heap.session.keys.okm, sizeof(heap.session.keys.okm));
#endif /* WITH_TRAP */

  id_context->len = ID_CONTEXT_SIZE;

  PT_END(&pt);
}
/*---------------------------------------------------------------------------*/
static int
disclose(
#if WITH_TRAP
  uint8_t clients_fhmqv_mic[FHMQV_MIC_LEN]
#endif /* WITH_TRAP */
  )
{
  coap_register_response_handler(context, on_disclose_response);
  coap_pdu_t *pdu = coap_pdu_init(COAP_MESSAGE_CON,
                                  COAP_REQUEST_CODE_PUT,
                                  coap_new_message_id(session),
                                  coap_opt_encode_size(COAP_OPTION_URI_PATH,
                                                       sizeof(disclose_uri)
                                                       - 1)
                                  + PAYLOAD_MARKER_SIZE
#if WITH_TRAP
                                  + FHMQV_MIC_LEN
#endif /* WITH_TRAP */
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
#if WITH_TRAP
  uint8_t *payload = coap_add_data_after(pdu,
                                         FHMQV_MIC_LEN
                                         + sizeof(master_secret_to_share));
  if(!payload) {
    LOG_ERR("coap_add_data_after failed\n");
    coap_delete_pdu(pdu);
    return 0;
  }
  memcpy(payload, clients_fhmqv_mic, FHMQV_MIC_LEN);
  memcpy(payload + FHMQV_MIC_LEN,
         master_secret_to_share,
         sizeof(master_secret_to_share));
#else /* WITH_TRAP */
  if(!coap_add_data(pdu,
                    sizeof(master_secret_to_share),
                    master_secret_to_share)) {
    LOG_ERR("coap_add_data failed\n");
    coap_delete_pdu(pdu);
    return 0;
  }
#endif /* WITH_TRAP */
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
  etimer_set(&heap.session.update_timer, INACTIVITY_TIMEOUT * CLOCK_SECOND);
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
  heap.session.last_update_mid = coap_send(session, pdu);
  return heap.session.last_update_mid != COAP_INVALID_MID;
}
/*---------------------------------------------------------------------------*/
static coap_response_t
on_response(coap_session_t *session,
            const coap_pdu_t *sent,
            const coap_pdu_t *received,
            const coap_mid_t mid)
{
  if(mid == heap.session.last_update_mid) {
    LOG_INFO("on_update_response\n");
    filtering_client_prolong();
    process_poll(&filtering_client_process);
    return COAP_RESPONSE_OK;
  }
#ifdef AGGREGATOR
  if(mid == heap.session.last_otp_mid) {
    if(!is_connected) {
      LOG_ERR("on_otp_response while not being connected\n");
      return COAP_RESPONSE_OK;
    }
    if(ctimer_expired(&heap.session.otp_timeout)) {
      LOG_ERR("late OTP response - we might need to extend our timeout\n");
      return COAP_RESPONSE_OK;
    }

    size_t payload_len;
    const uint8_t *payload;
    coap_get_data(received, &payload_len, &payload);
    if(payload_len != CSL_FRAMER_POTR_OTP_LEN) {
      LOG_ERR("OTP has unexpected length\n");
      ctimer_stop(&heap.session.otp_timeout);
      on_got_otp_result(NULL);
      return COAP_RESPONSE_FAIL;
    }
    heap.session.got_filtering_otp = true;
    memcpy(heap.session.filtering_otp, payload, CSL_FRAMER_POTR_OTP_LEN);
    filtering_client_prolong();
    ctimer_stop(&heap.session.otp_timeout);
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

  assert(ctimer_expired(&heap.session.otp_timeout));
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
  heap.session.last_otp_mid = coap_send(session, pdu);
  if(heap.session.last_otp_mid == COAP_INVALID_MID) {
    LOG_ERR("coap_send failed\n");
    *successful = false;
    PT_EXIT(&pt);
  }
  ctimer_set(&heap.session.otp_timeout,
             CLOCK_SECOND / (1000 / AGGREGATOR_OTP_WAIT_TIME),
             on_got_otp_result,
             NULL);
  heap.session.process_to_notify = process_current;
  heap.session.got_filtering_otp = false;
  heap.session.got_result = false;
  PT_WAIT_UNTIL(&pt, heap.session.got_result);
  *successful = heap.session.got_filtering_otp;
  if(timeout_flag) {
    process_poll(&filtering_client_process);
  }

  PT_END(&pt);
}
/*---------------------------------------------------------------------------*/
static void
on_got_otp_result(void *ptr)
{
  heap.session.got_result = true;
  process_poll(heap.session.process_to_notify);
}
/*---------------------------------------------------------------------------*/
void
filtering_client_get_filtering_otp(uint8_t dst[CSL_FRAMER_POTR_OTP_LEN])
{
  memcpy(dst, heap.session.filtering_otp, CSL_FRAMER_POTR_OTP_LEN);
}
/*---------------------------------------------------------------------------*/
#else /* AGGREGATOR */
bool
filtering_client_set_otp_key(void)
{
  if(!can_set_otp_key) {
    return false;
  }
#if WITH_CC2538_OPTIMIZATION
  cc2538_aes_128_active_key_area = OTP_KEY_AREA;
  return true;
#else /* WITH_CC2538_OPTIMIZATION */
  return CCM_STAR.set_key(heap.session.keys.otp_key);
#endif /* WITH_CC2538_OPTIMIZATION */
}
/*---------------------------------------------------------------------------*/
bool
filtering_client_unset_otp_key(void)
{
#if WITH_CC2538_OPTIMIZATION
  cc2538_aes_128_active_key_area = CC2538_AES_128_KEY_AREA;
  return true;
#else /* WITH_CC2538_OPTIMIZATION */
  return false;
#endif /* WITH_CC2538_OPTIMIZATION */
}
#endif /* AGGREGATOR */
/*---------------------------------------------------------------------------*/

/** @} */
