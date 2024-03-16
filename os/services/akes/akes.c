/*
 * Copyright (c) 2015, Hasso-Plattner-Institut.
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
 * \addtogroup akes
 * @{
 * \file
 *         Realizes AKES' three-way handshake.
 * \author
 *         Konrad Krentz <konrad.krentz@gmail.com>
 */

#include "akes/akes-delete.h"
#include "akes/akes-mac.h"
#include "akes/akes-trickle.h"
#include "akes/akes.h"
#include "lib/assert.h"
#include "lib/csprng.h"
#include "lib/leaky-bucket.h"
#include "lib/memb.h"
#include "net/mac/anti-replay.h"
#include "net/mac/cmd-broker.h"
#include "net/mac/frame-queue.h"
#include "net/netstack.h"
#include "net/packetbuf.h"
#include "net/queuebuf.h"
#include "sys/clock.h"
#include <stdbool.h>
#include <string.h>

#ifdef AKES_CONF_MAX_RETRANSMISSIONS_OF_HELLOACKS_AND_ACKS
#define MAX_RETRANSMISSIONS_OF_HELLOACKS_AND_ACKS \
    AKES_CONF_MAX_RETRANSMISSIONS_OF_HELLOACKS_AND_ACKS
#else /* AKES_CONF_MAX_RETRANSMISSIONS_OF_HELLOACKS_AND_ACKS */
#define MAX_RETRANSMISSIONS_OF_HELLOACKS_AND_ACKS (2)
#endif /* AKES_CONF_MAX_RETRANSMISSIONS_OF_HELLOACKS_AND_ACKS */

#ifdef AKES_CONF_MAX_RETRANSMISSIONS_OF_UPDATES
#define MAX_RETRANSMISSIONS_OF_UPDATES AKES_CONF_MAX_RETRANSMISSIONS_OF_UPDATES
#else /* AKES_CONF_MAX_RETRANSMISSIONS_OF_UPDATES */
#define MAX_RETRANSMISSIONS_OF_UPDATES (5)
#endif /* AKES_CONF_MAX_RETRANSMISSIONS_OF_UPDATES */

#ifdef AKES_CONF_HELLOACK_AND_ACK_DELAY
#define AKES_HELLOACK_AND_ACK_DELAY AKES_CONF_HELLOACK_AND_ACK_DELAY
#else /* AKES_CONF_HELLOACK_AND_ACK_DELAY */
#define AKES_HELLOACK_AND_ACK_DELAY (5) /* seconds */
#endif /* AKES_CONF_HELLOACK_AND_ACK_DELAY */

#if AKES_MAX_WAITING_PERIOD < (2 * AKES_HELLOACK_AND_ACK_DELAY)
#error "waiting period is too short"
#endif

#ifdef AKES_CONF_MAX_HELLO_RATE
#define MAX_HELLO_RATE AKES_CONF_MAX_HELLO_RATE
#else /* AKES_CONF_MAX_HELLO_RATE */
#define MAX_HELLO_RATE (5 * 60) /* 1 HELLO per 5min */
#endif /* AKES_CONF_MAX_HELLO_RATE */

#ifdef AKES_CONF_MAX_CONSECUTIVE_HELLOS
#define MAX_CONSECUTIVE_HELLOS AKES_CONF_MAX_CONSECUTIVE_HELLOS
#else /* AKES_CONF_MAX_CONSECUTIVE_HELLOS */
#define MAX_CONSECUTIVE_HELLOS (10)
#endif /* AKES_CONF_MAX_CONSECUTIVE_HELLOS */

#ifdef AKES_CONF_MAX_HELLOACK_RATE
#define MAX_HELLOACK_RATE AKES_CONF_MAX_HELLOACK_RATE
#else /* AKES_CONF_MAX_HELLOACK_RATE */
#define MAX_HELLOACK_RATE (150) /* 1 HELLOACK per 150s */
#endif /* AKES_CONF_MAX_HELLOACK_RATE */

#ifdef AKES_CONF_MAX_CONSECUTIVE_HELLOACKS
#define MAX_CONSECUTIVE_HELLOACKS AKES_CONF_MAX_CONSECUTIVE_HELLOACKS
#else /* AKES_CONF_MAX_CONSECUTIVE_HELLOACKS */
#define MAX_CONSECUTIVE_HELLOACKS (20)
#endif /* AKES_CONF_MAX_CONSECUTIVE_HELLOACKS */

#ifdef AKES_CONF_MAX_ACK_RATE
#define MAX_ACK_RATE AKES_CONF_MAX_ACK_RATE
#else /* AKES_CONF_MAX_ACK_RATE */
#define MAX_ACK_RATE MAX_HELLOACK_RATE
#endif /* AKES_CONF_MAX_ACK_RATE */

#ifdef AKES_CONF_MAX_CONSECUTIVE_ACKS
#define MAX_CONSECUTIVE_ACKS AKES_CONF_MAX_CONSECUTIVE_ACKS
#else /* AKES_CONF_MAX_CONSECUTIVE_ACKS */
#define MAX_CONSECUTIVE_ACKS MAX_CONSECUTIVE_HELLOACKS
#endif /* AKES_CONF_MAX_CONSECUTIVE_ACKS */

#ifdef AKES_CONF_WITH_HELLOACK_SENT_CALLBACK
#define WITH_ON_HELLOACK_SENT_CALLBACK AKES_CONF_WITH_HELLOACK_SENT_CALLBACK
#else /* AKES_CONF_WITH_HELLOACK_SENT_CALLBACK */
#define WITH_ON_HELLOACK_SENT_CALLBACK MAC_CONF_WITH_CSMA
#endif /* AKES_CONF_WITH_HELLOACK_SENT_CALLBACK */

/* Log configuration */
#include "sys/log.h"
#define LOG_MODULE "AKES"
#define LOG_LEVEL LOG_LEVEL_MAC

static void on_hello_sent(void *ptr, int status, int transmissions);
static void retransmit_hello(void *ptr);
static void on_hello_done(void *ptr);
static void send_helloack(void *ptr);
static void on_helloack_sent(void *ptr, int status, int transmissions);
static void on_ack_timeout(void *ptr);
static void send_ack(struct akes_nbr_entry *entry, bool is_new);
static void on_ack_sent(void *ptr, int status, int transmissions);
static cmd_broker_result_t on_command(uint8_t cmd_id, uint8_t *payload);

/* A random challenge, which will be attached to HELLO commands */
static uint8_t hello_challenge[AKES_NBR_CHALLENGE_LEN];
static bool has_hello_challenge_changed;
static bool is_awaiting_helloacks;
static struct ctimer hello_timer;
static cmd_broker_subscription_t subscription = { NULL , on_command };
static leaky_bucket_t hello_bucket;
static leaky_bucket_t helloack_bucket;
static leaky_bucket_t ack_bucket;

/*---------------------------------------------------------------------------*/
uint8_t *
akes_get_hello_challenge(void)
{
  return hello_challenge;
}
/*---------------------------------------------------------------------------*/
static void
prepare_helloack_or_ack(uint8_t cmd_id,
    struct akes_nbr_entry *entry,
    enum akes_nbr_status status)
{
  uint8_t *payload = cmd_broker_prepare_command(cmd_id,
      akes_nbr_get_addr(entry));
  akes_mac_set_numbers(entry->refs[status]);
  packetbuf_set_attr(PACKETBUF_ATTR_MAX_MAC_TRANSMISSIONS,
      1 + MAX_RETRANSMISSIONS_OF_HELLOACKS_AND_ACKS);

  /* write payload */
  if(status) {
    akes_nbr_copy_challenge(payload, entry->tentative->challenge);
    payload += AKES_NBR_CHALLENGE_LEN;
  }
#if AKES_NBR_WITH_INDICES
  payload[0] = akes_nbr_index_of(entry->refs[status]);
  payload++;
#endif /* AKES_NBR_WITH_INDICES */

  payload = AKES_MAC_STRATEGY.write_piggyback(payload, cmd_id, entry);
  uint8_t payload_len = payload - ((uint8_t *)packetbuf_hdrptr());

#if AKES_NBR_WITH_GROUP_KEYS && PACKETBUF_WITH_UNENCRYPTED_BYTES
  akes_nbr_copy_key(payload, akes_mac_group_key);
  packetbuf_set_attr(PACKETBUF_ATTR_UNENCRYPTED_BYTES, payload_len);
  payload_len += AES_128_KEY_LENGTH;
#endif /* AKES_NBR_WITH_GROUP_KEYS && PACKETBUF_WITH_UNENCRYPTED_BYTES */
  packetbuf_set_datalen(payload_len);
}
/*---------------------------------------------------------------------------*/
static void
process_helloack_or_ack(struct akes_nbr_entry *entry,
    const uint8_t *data,
    uint8_t cmd_id,
    struct akes_nbr_tentative *meta)
{
  switch(cmd_id) {
  case AKES_ACK_IDENTIFIER:
    entry->permanent->sent_authentic_hello = true;
    entry->permanent->is_receiving_update = false;
    break;
  case AKES_HELLOACK_IDENTIFIER:
    entry->permanent->sent_authentic_hello = false;
    entry->permanent->is_receiving_update = false;
    break;
  }

#if LLSEC802154_USES_FRAME_COUNTER
  anti_replay_was_replayed(&entry->permanent->anti_replay_info);
#endif /* LLSEC802154_USES_FRAME_COUNTER */
  AKES_DELETE_STRATEGY.prolong_permanent_neighbor(entry->permanent);

#if AKES_NBR_WITH_INDICES
  entry->permanent->foreign_index = data[0];
  data++;
#endif /* AKES_NBR_WITH_INDICES */

#if AKES_NBR_WITH_SEQNOS
  entry->permanent->has_active_seqno = false;
#endif /* AKES_NBR_WITH_SEQNOS */

  data = AKES_MAC_STRATEGY.read_piggyback(data, cmd_id, entry, meta);

#if AKES_NBR_WITH_GROUP_KEYS
  akes_nbr_copy_key(entry->permanent->group_key, data);
#endif /* AKES_NBR_WITH_GROUP_KEYS */
}
/*---------------------------------------------------------------------------*/
/*
 * We use AES-128 as a key derivation function (KDF). This is possible due to
 * simple circumstances. Speaking in terms of the extract-then-expand paradigm
 * [RFC 5869], we can skip over the extraction step since we already have a
 * uniformly-distributed key which we want to expand into session keys. For
 * implementing the expansion step, we may just use AES-128 [Paar and Pelzl,
 * Understanding Cryptography].
 */
static bool
generate_pairwise_key(uint8_t *pairwise_key, const uint8_t *shared_secret)
{
  while(!AES_128.get_lock());
  bool result = AES_128.set_key(shared_secret)
      && AES_128.encrypt(pairwise_key);
  AES_128.release_lock();
  return result;
}
/*---------------------------------------------------------------------------*/
static void
change_hello_challenge(void)
{
  has_hello_challenge_changed = csprng_rand(hello_challenge,
      AKES_NBR_CHALLENGE_LEN);
}
/*---------------------------------------------------------------------------*/
void
akes_broadcast_hello(void)
{
  if(!has_hello_challenge_changed) {
    LOG_WARN("skipping HELLO as there was a CSPRNG error\n");
    on_hello_sent(NULL, MAC_TX_ERR, 0);
    return;
  }

  if(is_awaiting_helloacks) {
    LOG_WARN("still waiting for HELLOACKs\n");
    return;
  }

  if(leaky_bucket_is_full(&hello_bucket)) {
    LOG_WARN("HELLO bucket is full\n");
    return;
  }
  leaky_bucket_pour(&hello_bucket);

  uint8_t *payload = cmd_broker_prepare_command(AKES_HELLO_IDENTIFIER,
      &linkaddr_null);
  akes_mac_set_numbers(NULL);

  /* write payload */
  akes_nbr_copy_challenge(payload, hello_challenge);
  payload += AKES_NBR_CHALLENGE_LEN;
  payload = AKES_MAC_STRATEGY.write_piggyback(payload,
      AKES_HELLO_IDENTIFIER,
      NULL);

  packetbuf_set_datalen(payload - ((uint8_t *)packetbuf_hdrptr()));

  LOG_INFO("broadcasting HELLO\n");
  is_awaiting_helloacks = true;
  AKES_MAC_STRATEGY.send(on_hello_sent, NULL);
}
/*---------------------------------------------------------------------------*/
static void
on_hello_sent(void *ptr, int status, int transmissions)
{
  switch(status) {
  case MAC_TX_DEFERRED:
    /* we expect another callback at a later point in time */
    break;
  case MAC_TX_QUEUE_FULL:
    ctimer_set(&hello_timer, CLOCK_SECOND, retransmit_hello, NULL);
    break;
  default:
    ctimer_set(&hello_timer,
        AKES_MAX_WAITING_PERIOD * CLOCK_SECOND,
        on_hello_done,
        NULL);
    break;
  }
}
/*---------------------------------------------------------------------------*/
static void
retransmit_hello(void *ptr)
{
  is_awaiting_helloacks = false;
  akes_broadcast_hello();
}
/*---------------------------------------------------------------------------*/
static void
on_hello_done(void *ptr)
{
  is_awaiting_helloacks = false;
  change_hello_challenge();
}
/*---------------------------------------------------------------------------*/
bool
akes_is_acceptable_hello(void)
{
  struct akes_nbr_entry *entry = akes_nbr_get_sender_entry();
  return (entry && entry->permanent)
      || (!(entry && entry->tentative)
          && !leaky_bucket_is_full(&helloack_bucket)
          && (akes_nbr_count(AKES_NBR_TENTATIVE) < AKES_NBR_MAX_TENTATIVES)
          && akes_nbr_free_slots());
}
/*---------------------------------------------------------------------------*/
static void
on_hello(const uint8_t *payload)
{
  LOG_INFO("received HELLO\n");

  struct akes_nbr_entry *entry = akes_nbr_get_sender_entry();
  if(entry && entry->permanent) {
    switch(AKES_MAC_STRATEGY.verify(entry->permanent)) {
    case AKES_MAC_VERIFY_RESULT_SUCCESS:
      AKES_MAC_STRATEGY.on_fresh_authentic_hello();
      AKES_DELETE_STRATEGY.prolong_permanent_neighbor(entry->permanent);
      akes_trickle_on_fresh_authentic_hello(entry->permanent);
      return;
    case AKES_MAC_VERIFY_RESULT_INAUTHENTIC:
      LOG_INFO("starting new session with permanent neighbor\n");
      break;
    case AKES_MAC_VERIFY_RESULT_REPLAYED:
      LOG_ERR("replayed HELLO\n");
      return;
    }
  }

  if(leaky_bucket_is_full(&helloack_bucket)) {
    LOG_WARN("HELLOACK bucket is full\n");
    return;
  }

  if(entry && entry->tentative) {
    LOG_WARN("received HELLO from tentative neighbor\n");
    return;
  }

  /* Create tentative neighbor */
  entry = akes_nbr_new(AKES_NBR_TENTATIVE);
  if(!entry) {
    LOG_WARN("HELLO flood?\n");
    return;
  }

  leaky_bucket_pour(&helloack_bucket);

  akes_nbr_copy_challenge(entry->tentative->challenge, payload);
  AKES_MAC_STRATEGY.read_piggyback(payload + AKES_NBR_CHALLENGE_LEN,
      AKES_HELLO_IDENTIFIER,
      entry,
      NULL);

  clock_time_t waiting_period = clock_random(CLOCK_SECOND
      * (AKES_MAX_WAITING_PERIOD - (2 * AKES_HELLOACK_AND_ACK_DELAY)));
  ctimer_set(&entry->tentative->meta->wait_timer,
      waiting_period,
      send_helloack,
      entry);
  entry->tentative->meta->was_helloack_sent = false;
  entry->tentative->meta->was_cloned = false;
  entry->tentative->meta->helloack_transmissions = 0;
  LOG_INFO("will send HELLOACK in %"CLOCK_PRI"s\n",
      waiting_period / CLOCK_SECOND);
}
/*---------------------------------------------------------------------------*/
static void
send_helloack(void *ptr)
{
  LOG_INFO("sending HELLOACK\n");

  struct akes_nbr_entry *entry = (struct akes_nbr_entry *)ptr;
  assert(entry
      && entry->tentative
      && (entry == akes_nbr_get_entry_of(entry->tentative)));

  uint8_t challenges[2 * AKES_NBR_CHALLENGE_LEN];
  akes_nbr_copy_challenge(challenges, entry->tentative->challenge);
  if(!csprng_rand(challenges + AKES_NBR_CHALLENGE_LEN,
      AKES_NBR_CHALLENGE_LEN)) {
    LOG_ERR("CSPRNG failed\n");
    akes_nbr_delete(entry, AKES_NBR_TENTATIVE);
    return;
  }
  akes_nbr_copy_challenge(entry->tentative->challenge,
      challenges + AKES_NBR_CHALLENGE_LEN);

  /* write payload */
  prepare_helloack_or_ack(
      entry->permanent ? AKES_HELLOACK_P_IDENTIFIER : AKES_HELLOACK_IDENTIFIER,
      entry,
      AKES_NBR_TENTATIVE);

  /* generate pairwise key */
  const uint8_t *secret = AKES_SCHEME.get_secret_with_hello_sender(
      akes_nbr_get_addr(entry));
  if(!secret || !generate_pairwise_key(challenges, secret)) {
    LOG_ERR("no secret with HELLO sender or AES error\n");
    akes_nbr_delete(entry, AKES_NBR_TENTATIVE);
    return;
  }
  akes_nbr_copy_key(entry->tentative->tentative_pairwise_key, challenges);
#if !WITH_ON_HELLOACK_SENT_CALLBACK
  ctimer_set(&entry->tentative->meta->wait_timer,
      CLOCK_SECOND * AKES_HELLOACK_AND_ACK_DELAY * 2,
      on_ack_timeout,
      entry);
  entry->tentative->meta->was_helloack_sent = true;
#endif /* !WITH_ON_HELLOACK_SENT_CALLBACK */
  AKES_MAC_STRATEGY.send(on_helloack_sent, entry);
}
/*---------------------------------------------------------------------------*/
static void
on_helloack_sent(void *ptr, int status, int transmissions)
{
  if(status == MAC_TX_DEFERRED) {
    /* we expect another callback at a later point in time */
    return;
  }

  LOG_INFO("on_helloack_sent\n");

  struct akes_nbr_entry *entry = (struct akes_nbr_entry *)ptr;
#if WITH_ON_HELLOACK_SENT_CALLBACK
  assert(entry
      && entry->tentative
      && (entry == akes_nbr_get_entry_of(entry->tentative)));
#else /* WITH_ON_HELLOACK_SENT_CALLBACK */
  if(!entry
      || !entry->tentative
      || (entry != akes_nbr_get_entry_of(entry->tentative))) {
    LOG_WARN("apparently on_ack_timeout occurred in the meantime\n");
    return;
  }
#endif /* WITH_ON_HELLOACK_SENT_CALLBACK */
  entry->tentative->meta->helloack_transmissions = transmissions;

#if WITH_ON_HELLOACK_SENT_CALLBACK
  if(status != MAC_TX_OK) {
    LOG_ERR("HELLOACK transmission failed\n");
    /* TODO retransmit if status == MAC_TX_QUEUE_FULL */
    akes_nbr_delete(entry, AKES_NBR_TENTATIVE);
    return;
  }
  entry->tentative->meta->was_helloack_sent = true;
  ctimer_set(&entry->tentative->meta->wait_timer,
      CLOCK_SECOND * AKES_HELLOACK_AND_ACK_DELAY,
      on_ack_timeout,
      entry);
  AKES_MAC_STRATEGY.on_helloack_sent(entry->tentative);
#endif /* WITH_ON_HELLOACK_SENT_CALLBACK */
}
/*---------------------------------------------------------------------------*/
static void
on_ack_timeout(void *ptr)
{
  LOG_INFO("on_ack_timeout\n");

  struct akes_nbr_entry *entry = (struct akes_nbr_entry *)ptr;
  assert(entry
      && entry->tentative
      && (entry == akes_nbr_get_entry_of(entry->tentative)));

  akes_nbr_delete(entry, AKES_NBR_TENTATIVE);
}
/*---------------------------------------------------------------------------*/
bool
akes_is_acceptable_helloack(void)
{
  if(!is_awaiting_helloacks
      || leaky_bucket_is_full(&ack_bucket)) {
    LOG_ERR("unacceptable HELLOACK\n");
    return false;
  }
  return true;
}
/*---------------------------------------------------------------------------*/
static void
on_helloack(const uint8_t *payload, int p_flag)
{
  LOG_INFO("received HELLOACK\n");

  if(!akes_is_acceptable_helloack()) {
    LOG_ERR("unacceptable HELLOACK\n");
    return;
  }

  struct akes_nbr_entry *entry = akes_nbr_get_sender_entry();
  if(entry && entry->permanent && p_flag) {
    LOG_INFO("no need to start a new session\n");
    return;
  }

  const uint8_t *secret = AKES_SCHEME.get_secret_with_helloack_sender(
      packetbuf_addr(PACKETBUF_ADDR_SENDER));
  if(!secret) {
    LOG_ERR("no secret with HELLOACK sender\n");
    return;
  }

  /* copy challenges and generate key */
  uint8_t key[AKES_NBR_CHALLENGE_LEN * 2];
  akes_nbr_copy_challenge(key, hello_challenge);
  akes_nbr_copy_challenge(key + AKES_NBR_CHALLENGE_LEN, payload);
  if(!generate_pairwise_key(key, secret)) {
    LOG_ERR("AES error\n");
    return;
  }

  if(!akes_mac_unsecure(key)) {
    LOG_ERR("inauthentic HELLOACK\n");
    return;
  }

  bool is_new = true;
  if(entry) {
    if(entry->permanent) {
#if AKES_NBR_WITH_PAIRWISE_KEYS || AKES_NBR_CACHE_HELLOACK_CHALLENGE
      if(
#if AKES_NBR_WITH_PAIRWISE_KEYS
         !memcmp(key,
             entry->permanent->pairwise_key,
             sizeof(entry->permanent->pairwise_key))) {
#else /* AKES_NBR_WITH_PAIRWISE_KEYS */
         !memcmp(payload,
             entry->permanent->helloack_challenge,
             sizeof(entry->permanent->helloack_challenge))) {
#endif /* AKES_NBR_WITH_PAIRWISE_KEYS */

        LOG_ERR("replayed HELLOACK\n");
        return;
      } else
#endif /* AKES_NBR_WITH_PAIRWISE_KEYS || AKES_NBR_CACHE_HELLOACK_CHALLENGE */
      {
        akes_nbr_delete(entry, AKES_NBR_PERMANENT);
        is_new = false;
      }
    }

    if(entry->tentative) {
      if(!entry->tentative->meta->was_helloack_sent
          && !ctimer_expired(&entry->tentative->meta->wait_timer)) {
        LOG_INFO("skipping HELLOACK\n");
        ctimer_stop(&entry->tentative->meta->wait_timer);
        akes_nbr_delete(entry, AKES_NBR_TENTATIVE);
      } else {
        LOG_WARN("awaiting ACK\n");
        AKES_MAC_STRATEGY.on_fresh_authentic_helloack();
        return;
      }
    }
  }
  AKES_MAC_STRATEGY.on_fresh_authentic_helloack();

  entry = akes_nbr_new(AKES_NBR_PERMANENT);
  if(!entry) {
    LOG_ERR("failed to create permanent neighbor\n");
    return;
  }

#if AKES_NBR_WITH_PAIRWISE_KEYS
  akes_nbr_copy_key(entry->permanent->pairwise_key, key);
#else /* AKES_NBR_WITH_PAIRWISE_KEYS */
#if AKES_NBR_CACHE_HELLOACK_CHALLENGE
  memcpy(entry->permanent->helloack_challenge,
      payload,
      sizeof(entry->permanent->helloack_challenge));
#endif /* AKES_NBR_CACHE_HELLOACK_CHALLENGE */
  akes_nbr_new(AKES_NBR_TENTATIVE);
  if(!entry->tentative) {
    akes_nbr_delete(entry, AKES_NBR_PERMANENT);
    LOG_ERR("failed to create tentative neighbor\n");
    return;
  }
  entry->tentative->meta->was_helloack_sent = false;
  entry->tentative->meta->was_cloned = false;
  assert(ctimer_expired(&entry->tentative->meta->wait_timer));
  akes_nbr_copy_key(entry->tentative->tentative_pairwise_key, key);
#endif /* AKES_NBR_WITH_PAIRWISE_KEYS */
  process_helloack_or_ack(entry,
      payload + AKES_NBR_CHALLENGE_LEN,
      AKES_HELLOACK_IDENTIFIER,
      NULL);
  send_ack(entry, is_new);
}
/*---------------------------------------------------------------------------*/
static void
send_ack(struct akes_nbr_entry *entry, bool is_new)
{
  LOG_INFO("sending ACK\n");
  leaky_bucket_pour(&ack_bucket);
  prepare_helloack_or_ack(AKES_ACK_IDENTIFIER, entry, AKES_NBR_PERMANENT);
  AKES_MAC_STRATEGY.send(on_ack_sent, (void *)is_new);
}
/*---------------------------------------------------------------------------*/
static void
on_ack_sent(void *is_new, int status, int transmissions)
{
  if(status == MAC_TX_DEFERRED) {
    /* we expect another callback at a later point in time */
    return;
  }
  /* TODO retransmit if status == MAC_TX_QUEUE_FULL */

  akes_mac_report_to_network_layer(status, transmissions);

  struct akes_nbr_entry *entry = akes_nbr_get_receiver_entry();
  if(!entry) {
    LOG_ERR("entry has been deleted\n");
    return;
  }
#if !AKES_NBR_WITH_PAIRWISE_KEYS
  assert(entry->tentative);
  akes_nbr_delete(entry, AKES_NBR_TENTATIVE);
#endif /* !AKES_NBR_WITH_PAIRWISE_KEYS */
  assert(entry->permanent);
  if(status != MAC_TX_OK) {
    LOG_ERR("ACK was not acknowledged\n");
    akes_nbr_delete(entry, AKES_NBR_PERMANENT);
    return;
  }
  if(is_new) {
    akes_trickle_on_new_nbr();
  }
}
/*---------------------------------------------------------------------------*/
bool
akes_is_acceptable_ack(const struct akes_nbr_entry *entry)
{
  return entry
      && entry->tentative
      && entry->tentative->meta->was_helloack_sent;
}
/*---------------------------------------------------------------------------*/
static void
on_ack(const uint8_t *payload)
{
  bool is_new;
  struct akes_nbr_tentative *meta;

  LOG_INFO("received ACK\n");

  struct akes_nbr_entry *entry = akes_nbr_get_sender_entry();
  if(!akes_is_acceptable_ack(entry)) {
    LOG_ERR("invalid ACK\n");
    return;
  }
  meta = entry->tentative->meta;
  assert(!ctimer_expired(&meta->wait_timer));
  if(meta->was_cloned) {
    LOG_INFO("was already turned into a permanent neighbor\n");
    return;
  }
#if AKES_MAC_UNSECURE_UNICASTS
  if(!akes_mac_unsecure(entry->tentative->tentative_pairwise_key)) {
    LOG_ERR("invalid ACK\n");
    return;
  }
#endif /* AKES_MAC_UNSECURE_UNICASTS */

  if(entry->permanent) {
    akes_nbr_delete(entry, AKES_NBR_PERMANENT);
    is_new = false;
  } else {
    is_new = true;
  }
  entry->permanent = entry->tentative;
  entry->tentative = akes_nbr_clone(entry->tentative);
  process_helloack_or_ack(entry, payload, AKES_ACK_IDENTIFIER, meta);
#if !WITH_ON_HELLOACK_SENT_CALLBACK
  if(!meta->helloack_transmissions) {
    LOG_INFO("canceling ongoing HELLOACK transmission\n");
    for(frame_queue_entry_t *fqe = frame_queue_head();
        fqe;
        fqe = frame_queue_next(fqe)) {
      queuebuf_to_packetbuf(fqe->qb);
      if(akes_mac_is_helloack() && linkaddr_cmp(akes_nbr_get_addr(entry),
          packetbuf_addr(PACKETBUF_ADDR_RECEIVER))) {
        frame_queue_on_transmitted(MAC_TX_OK, fqe);
        break;
      }
    }
  }
#endif /* !WITH_ON_HELLOACK_SENT_CALLBACK */
  LOG_DBG("%u HELLOACK transmissions\n", meta->helloack_transmissions);
  akes_mac_report_to_network_layer_with_address(akes_nbr_get_addr(entry),
      MAC_TX_OK,
      meta->helloack_transmissions);
  if(!entry->tentative) {
    ctimer_stop(&meta->wait_timer);
    akes_nbr_free_tentative_metadata(meta);
  } else {
    meta->was_cloned = true;
  }
  if(is_new) {
    akes_trickle_on_new_nbr();
  }
}
/*---------------------------------------------------------------------------*/
void
akes_send_update(struct akes_nbr_entry *entry)
{
  uint8_t *payload = cmd_broker_prepare_command(AKES_UPDATE_IDENTIFIER,
      akes_nbr_get_addr(entry));
  akes_mac_set_numbers(entry->permanent);
  packetbuf_set_attr(PACKETBUF_ATTR_MAX_MAC_TRANSMISSIONS,
      1 + MAX_RETRANSMISSIONS_OF_UPDATES);
  payload = AKES_MAC_STRATEGY.write_piggyback(payload,
      AKES_UPDATE_IDENTIFIER,
      entry);
  uint8_t payload_len = payload - ((uint8_t *)packetbuf_hdrptr());
  packetbuf_set_datalen(payload_len);
  AKES_MAC_STRATEGY.send(akes_delete_on_update_sent, NULL);
}
/*---------------------------------------------------------------------------*/
static void
on_update(uint8_t cmd_id, const uint8_t *payload)
{
  LOG_INFO("received UPDATE\n");

  struct akes_nbr_entry *entry = akes_mac_check_frame();
  if(!entry) {
    LOG_ERR("invalid UPDATE\n");
    return;
  }
  AKES_MAC_STRATEGY.read_piggyback(payload, cmd_id, entry, NULL);
}
/*---------------------------------------------------------------------------*/
static cmd_broker_result_t
on_command(uint8_t cmd_id, uint8_t *payload)
{
#if AKES_NBR_WITH_GROUP_KEYS && PACKETBUF_WITH_UNENCRYPTED_BYTES
  switch(cmd_id) {
  case AKES_HELLOACK_IDENTIFIER:
  case AKES_HELLOACK_P_IDENTIFIER:
#if AKES_MAC_UNSECURE_UNICASTS
  case AKES_ACK_IDENTIFIER:
#endif /* AKES_MAC_UNSECURE_UNICASTS */
    packetbuf_set_attr(PACKETBUF_ATTR_UNENCRYPTED_BYTES,
        packetbuf_datalen()
            - AES_128_KEY_LENGTH
            - AKES_MAC_UNICAST_MIC_LEN);
    break;
  }
#endif /* AKES_NBR_WITH_GROUP_KEYS && PACKETBUF_WITH_UNENCRYPTED_BYTES */

  switch(cmd_id) {
  case AKES_HELLO_IDENTIFIER:
    on_hello(payload);
    break;
  case AKES_HELLOACK_IDENTIFIER:
    on_helloack(payload, 0);
    break;
  case AKES_HELLOACK_P_IDENTIFIER:
    on_helloack(payload, 1);
    break;
  case AKES_ACK_IDENTIFIER:
    on_ack(payload);
    break;
  case AKES_UPDATE_IDENTIFIER:
    on_update(cmd_id, payload);
    break;
  default:
    return CMD_BROKER_UNCONSUMED;
  }
  return CMD_BROKER_CONSUMED;
}
/*---------------------------------------------------------------------------*/
enum akes_nbr_status
akes_get_receiver_status(void)
{
  if(!packetbuf_holds_cmd_frame()) {
    return AKES_NBR_PERMANENT;
  }

  switch(packetbuf_get_dispatch_byte()) {
#if !AKES_NBR_WITH_PAIRWISE_KEYS
  case AKES_ACK_IDENTIFIER:
#endif /* !AKES_NBR_WITH_PAIRWISE_KEYS */
  case AKES_HELLOACK_IDENTIFIER:
  case AKES_HELLOACK_P_IDENTIFIER:
    return AKES_NBR_TENTATIVE;
  default:
    return AKES_NBR_PERMANENT;
  }
}
/*---------------------------------------------------------------------------*/
void
akes_init(void)
{
  change_hello_challenge();
  leaky_bucket_init(&hello_bucket,
      MAX_CONSECUTIVE_HELLOS,
      MAX_HELLO_RATE);
  leaky_bucket_init(&helloack_bucket,
      MAX_CONSECUTIVE_HELLOACKS,
      MAX_HELLOACK_RATE);
  leaky_bucket_init(&ack_bucket,
      MAX_CONSECUTIVE_ACKS,
      MAX_ACK_RATE);
  cmd_broker_subscribe(&subscription);
  akes_nbr_init();
  AKES_SCHEME.init();
  akes_delete_init();
  akes_broadcast_hello();
  akes_trickle_start();
}
/*---------------------------------------------------------------------------*/

/** @} */
