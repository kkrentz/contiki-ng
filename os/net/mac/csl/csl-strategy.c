/*
 * Copyright (c) 2018, Hasso-Plattner-Institut.
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
 * \addtogroup csl
 * @{
 * \file
 *         An AKES-strategy that exclusively uses pairwise session keys
 * \author
 *         Konrad Krentz <konrad.krentz@gmail.com>
 */

#include "net/mac/csl/csl-strategy.h"
#include "lib/assert.h"
#include "lib/csprng.h"
#include "lib/memb.h"
#include "net/mac/csl/csl-ccm-inputs.h"
#include "net/mac/csl/csl-channel-selector.h"
#include "net/mac/csl/csl-framer-potr.h"
#include "net/mac/csl/csl-nbr.h"
#include "net/nbr-table.h"
#include "net/packetbuf.h"
#include "net/queuebuf.h"
#include "services/akes/akes.h"
#include <stddef.h>

/* Log configuration */
#include "sys/log.h"
#define LOG_MODULE "CSL-strategy"
#define LOG_LEVEL LOG_LEVEL_MAC

#ifdef CSL_STRATEGY_CONF_MAX_RETRANSMISSIONS
#define MAX_RETRANSMISSIONS CSL_STRATEGY_CONF_MAX_RETRANSMISSIONS
#else /* CSL_STRATEGY_CONF_MAX_RETRANSMISSIONS */
#define MAX_RETRANSMISSIONS 2
#endif /* CSL_STRATEGY_CONF_MAX_RETRANSMISSIONS */

struct ongoing_broadcast {
  uint32_t neighbor_bitmap;
  void *ptr;
  mac_callback_t sent;
};

#if !CSL_COMPLIANT
#if NBR_TABLE_MAX_NEIGHBORS > ( \
    (RADIO_MAX_PAYLOAD \
        - AKES_HELLO_DATALEN \
        - CSL_FRAMER_POTR_HELLO_PIGGYBACK_LEN) / AKES_MAC_BROADCAST_MIC_LEN)
#error NBR_TABLE_MAX_NEIGHBORS is too big
#endif

static void send_broadcast(struct ongoing_broadcast *ob);
static void on_broadcast_sent(void *ptr, int status, int transmissions);
MEMB(ongoing_broadcasts_memb, struct ongoing_broadcast, QUEUEBUF_NUM);
static uint8_t q[AKES_NBR_CHALLENGE_LEN];
static rtimer_clock_t phi_2;

/*---------------------------------------------------------------------------*/
static void
send(mac_callback_t sent, void *ptr)
{
  if(!akes_mac_is_hello() && packetbuf_holds_broadcast()) {
    struct ongoing_broadcast *ob = memb_alloc(&ongoing_broadcasts_memb);
    if(!ob) {
      LOG_ERR("ongoing_broadcasts_memb is full\n");
      mac_call_sent_callback(sent, ptr, MAC_TX_ERR, 0);
      return;
    }
    assert(NBR_TABLE_MAX_NEIGHBORS <= (sizeof(ob->neighbor_bitmap) * 8));
    ob->neighbor_bitmap = 0;
    ob->sent = sent;
    ob->ptr = ptr;
    send_broadcast(ob);
  } else {
    AKES_MAC_DECORATED_MAC.send(sent, ptr);
  }
}
/*---------------------------------------------------------------------------*/
static void
send_broadcast(struct ongoing_broadcast *ob)
{
  /* find a permanent neighbor that has not received this frame, yet */
  struct akes_nbr_entry *entry;
  for(entry = akes_nbr_head(AKES_NBR_PERMANENT);
      entry;
      entry = akes_nbr_next(entry, AKES_NBR_PERMANENT)) {
    if(!((1 << akes_nbr_index_of(entry->permanent)) & ob->neighbor_bitmap)) {
      break;
    }
  }

  if(!entry) {
    memb_free(&ongoing_broadcasts_memb, ob);
    packetbuf_set_addr(PACKETBUF_ADDR_RECEIVER, &linkaddr_null);
    mac_call_sent_callback(ob->sent, ob->ptr, MAC_TX_OK, 0);
    return;
  }

  ob->neighbor_bitmap |= 1 << akes_nbr_index_of(entry->permanent);
  packetbuf_set_addr(PACKETBUF_ADDR_RECEIVER, akes_nbr_get_addr(entry));
  packetbuf_set_attr(PACKETBUF_ATTR_MAX_MAC_TRANSMISSIONS,
      1 + MAX_RETRANSMISSIONS);
  akes_mac_set_numbers(entry->permanent);
  AKES_MAC_DECORATED_MAC.send(on_broadcast_sent, ob);
}
/*---------------------------------------------------------------------------*/
static void
on_broadcast_sent(void *ptr, int status, int transmissions)
{
  if(status == MAC_TX_DEFERRED) {
    return;
  }
  akes_mac_report_to_network_layer(status, transmissions);
  send_broadcast(ptr);
}
/*---------------------------------------------------------------------------*/
static int
on_frame_created(void)
{
  uint8_t *dataptr = packetbuf_dataptr();
  uint16_t datalen = packetbuf_datalen();
  if(akes_mac_is_hello()) {
    ssize_t max_index = -1;
    for(struct akes_nbr_entry *entry = akes_nbr_head(AKES_NBR_PERMANENT);
        entry;
        entry = akes_nbr_next(entry, AKES_NBR_PERMANENT)) {
      ssize_t local_index = akes_nbr_index_of(entry->permanent);
      if(!akes_mac_aead(entry->permanent->pairwise_key,
            false,
            dataptr + datalen + (local_index * AKES_MAC_BROADCAST_MIC_LEN),
            true)) {
        LOG_ERR("akes_mac_aead failed\n");
        return 0;
      }
      if(local_index > max_index) {
        max_index = local_index;
      }
    }
    if(max_index >= 0) {
      packetbuf_set_datalen(datalen
          + ((max_index + 1) * AKES_MAC_BROADCAST_MIC_LEN));
    }
  } else {
    enum akes_nbr_status status = akes_get_receiver_status();
    struct akes_nbr_entry *entry = akes_nbr_get_receiver_entry();
    if(!entry || !entry->refs[status]) {
      return 0;
    }

    if(!akes_mac_aead(entry->refs[status]->pairwise_key,
          akes_mac_get_sec_lvl() & (1 << 2),
          dataptr + datalen,
          true)) {
      LOG_ERR("akes_mac_aead failed\n");
      return 0;
    }
    packetbuf_set_datalen(datalen + AKES_MAC_UNICAST_MIC_LEN);
  }
  return 1;
}
/*---------------------------------------------------------------------------*/
static enum akes_mac_verify_result
verify(struct akes_nbr *sender)
{
  if(akes_mac_is_hello()) {
    uint8_t *dataptr = packetbuf_dataptr();
    packetbuf_set_datalen(
        AKES_HELLO_DATALEN + CSL_FRAMER_POTR_HELLO_PIGGYBACK_LEN);
    uint8_t *micptr = dataptr
        + AKES_HELLO_DATALEN
        + CSL_FRAMER_POTR_HELLO_PIGGYBACK_LEN
        + (sender->foreign_index * AKES_MAC_BROADCAST_MIC_LEN);
    uint8_t mic[AKES_MAC_BROADCAST_MIC_LEN];
    if(!akes_mac_aead(sender->pairwise_key, false, mic, false)
        || memcmp(micptr, mic, sizeof(mic))) {
      return AKES_MAC_VERIFY_RESULT_INAUTHENTIC;
    }
  } else {
    if(!akes_mac_unsecure(sender->pairwise_key)) {
      return AKES_MAC_VERIFY_RESULT_INAUTHENTIC;
    }
  }

  return AKES_MAC_VERIFY_RESULT_SUCCESS;
}
/*---------------------------------------------------------------------------*/
static uint8_t
get_overhead(void)
{
  return AKES_MAC_UNICAST_MIC_LEN;
}
/*---------------------------------------------------------------------------*/
static uint8_t *
write_piggyback(uint8_t *data, uint8_t cmd_id, struct akes_nbr_entry *entry)
{
  switch(cmd_id) {
  case AKES_HELLO_IDENTIFIER:
    data += WAKE_UP_COUNTER_LEN;
    break;
  case AKES_HELLOACK_IDENTIFIER:
  case AKES_HELLOACK_P_IDENTIFIER:
    data += CSL_FRAMER_POTR_HELLOACK_PIGGYBACK_LEN;
    break;
  case AKES_ACK_IDENTIFIER:
    csl_framer_potr_write_phase(data, phi_2);
    data += CSL_FRAMER_POTR_PHASE_LEN;
    akes_nbr_copy_challenge(data, q);
    data += AKES_NBR_CHALLENGE_LEN;
    break;
  default:
    break;
  }
  return data;
}
/*---------------------------------------------------------------------------*/
static const uint8_t *
read_piggyback(const uint8_t *data,
    uint8_t cmd_id,
    const struct akes_nbr_entry *entry,
    const struct akes_nbr_tentative *meta)
{
  csl_nbr_t *csl_nbr;
  switch(cmd_id) {
  case AKES_HELLO_IDENTIFIER:
    csl_nbr = csl_nbr_get(entry->tentative);
    csl_nbr->sync_data.t = csl_get_sfd_timestamp_of_last_payload_frame()
        - (WAKE_UP_COUNTER_INTERVAL / 2);
    csl_nbr->sync_data.his_wake_up_counter_at_t = wake_up_counter_parse(data);
    data += WAKE_UP_COUNTER_LEN;
    CSL_CHANNEL_SELECTOR.init(csl_nbr);
    break;
  case AKES_HELLOACK_IDENTIFIER:
  case AKES_HELLOACK_P_IDENTIFIER:
    csl_nbr = csl_nbr_get(entry->permanent);
    csl_nbr->sync_data.t = csl_get_sfd_timestamp_of_last_payload_frame()
        - (WAKE_UP_COUNTER_INTERVAL - csl_framer_potr_parse_phase(data));
    data += CSL_FRAMER_POTR_PHASE_LEN;
    csl_nbr->sync_data.his_wake_up_counter_at_t = wake_up_counter_parse(data);
    data +=  WAKE_UP_COUNTER_LEN;
    akes_nbr_copy_challenge(q, data);
    data += AKES_NBR_CHALLENGE_LEN;
    phi_2 = csl_get_phase(csl_get_sfd_timestamp_of_last_payload_frame());
    csl_nbr->drift = AKES_NBR_UNINITIALIZED_DRIFT;
    CSL_CHANNEL_SELECTOR.init(csl_nbr);
    break;
  case AKES_ACK_IDENTIFIER:
    csl_nbr = csl_nbr_get(entry->permanent);
    csl_nbr_tentative_t *csl_nbr_tentative = csl_nbr_get_tentative(meta);
    csl_nbr->sync_data.his_wake_up_counter_at_t =
        csl_nbr_tentative->predicted_wake_up_counter;
    csl_nbr->sync_data.t = csl_nbr_tentative->helloack_sfd_timestamp
        - (WAKE_UP_COUNTER_INTERVAL - csl_framer_potr_parse_phase(data));
    data += CSL_FRAMER_POTR_ACK_PIGGYBACK_LEN;
    csl_nbr->drift = AKES_NBR_UNINITIALIZED_DRIFT;
    csl_nbr->historical_sync_data = csl_nbr->sync_data;
    break;
  default:
    break;
  }
  return data;
}
/*---------------------------------------------------------------------------*/
static int
before_create(void)
{
  uint8_t *dataptr = packetbuf_dataptr();
  if(akes_mac_is_hello()) {
    wake_up_counter_write(dataptr + AKES_HELLO_PIGGYBACK_OFFSET,
        csl_get_wake_up_counter(csl_get_payload_frames_shr_end()));
  } else if(akes_mac_is_helloack()) {
    struct akes_nbr_entry *entry = akes_nbr_get_receiver_entry();
    struct akes_nbr *nbr;
    if(!entry || !((nbr = entry->tentative))) {
      return FRAMER_FAILED;
    }
    csl_nbr_tentative_t *csl_nbr_tentative = csl_nbr_get_tentative(nbr->meta);
    csl_nbr_tentative->helloack_sfd_timestamp = csl_get_payload_frames_shr_end();
    if(!csprng_rand(csl_nbr_tentative->q, AKES_NBR_CHALLENGE_LEN)) {
      LOG_ERR("CSPRNG error\n");
      return FRAMER_FAILED;
    }
    csl_nbr_tentative->predicted_wake_up_counter = csl_predict_wake_up_counter();

    dataptr += AKES_HELLOACK_PIGGYBACK_OFFSET;
    csl_framer_potr_write_phase(dataptr,
        csl_get_phase(csl_nbr_tentative->helloack_sfd_timestamp));
    dataptr += CSL_FRAMER_POTR_PHASE_LEN;
    wake_up_counter_write(dataptr,
        csl_get_wake_up_counter(csl_nbr_tentative->helloack_sfd_timestamp));
    dataptr += WAKE_UP_COUNTER_LEN;
    akes_nbr_copy_challenge(dataptr, csl_nbr_tentative->q);
  }
  return 0;
}
/*---------------------------------------------------------------------------*/
static void
on_helloack_sent(struct akes_nbr *nbr)
{
}
/*---------------------------------------------------------------------------*/
static void
on_fresh_authentic_hello(void)
{
  leaky_bucket_effuse(&csl_framer_potr_hello_inc_bucket);
}
/*---------------------------------------------------------------------------*/
static void
on_fresh_authentic_helloack(void)
{
  leaky_bucket_effuse(&csl_framer_potr_helloack_inc_bucket);
}
/*---------------------------------------------------------------------------*/
static void
init(void)
{
  memb_init(&ongoing_broadcasts_memb);
}
/*---------------------------------------------------------------------------*/
const struct akes_mac_strategy csl_strategy = {
  csl_ccm_inputs_generate_nonce,
  send,
  on_frame_created,
  verify,
  get_overhead,
  write_piggyback,
  read_piggyback,
  before_create,
  on_helloack_sent,
  on_fresh_authentic_hello,
  on_fresh_authentic_helloack,
  init
};
/*---------------------------------------------------------------------------*/
static bool
is_permanent_neighbor_expired(struct akes_nbr *nbr)
{
  csl_nbr_t *csl_nbr = csl_nbr_get(nbr);
  rtimer_clock_t delta = RTIMER_NOW() - csl_nbr->sync_data.t;
  return delta > (csl_nbr->drift == AKES_NBR_UNINITIALIZED_DRIFT
      ? RTIMER_SECOND * CSL_INITIAL_UPDATE_THRESHOLD
      : RTIMER_SECOND * CSL_SUBSEQUENT_UPDATE_THRESHOLD);
}
/*---------------------------------------------------------------------------*/
static void
prolong_permanent_neighbor(struct akes_nbr *nbr)
{
}
/*---------------------------------------------------------------------------*/
const struct akes_delete_strategy csl_strategy_delete = {
  is_permanent_neighbor_expired,
  prolong_permanent_neighbor
};
/*---------------------------------------------------------------------------*/

#endif /* !CSL_COMPLIANT */

/** @} */
