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
 *         Uses pairwise session keys for securing unicast frames
 *         and EBEAP for securing broadcast frames.
 * \author
 *         Konrad Krentz <konrad.krentz@gmail.com>
 */

#include "services/akes/akes.h"
#include "services/akes/akes-nbr.h"
#include "net/mac/anti-replay.h"
#include "net/nbr-table.h"
#include "net/packetbuf.h"
#include "net/queuebuf.h"
#include "net/netstack.h"
#include "net/mac/cmd-broker.h"
#include "net/mac/ccm-star-packetbuf.h"
#include "lib/memb.h"
#include "lib/list.h"
#include "dev/watchdog.h"
#include "net/mac/framer/crc16-framer.h"
#include <string.h>

#define MAX_BUFFERED_MICS 5
#define WITH_BROADCAST_ENCRYPTION (AKES_MAC_BROADCAST_SEC_LVL & (1 << 2))
#define ANNOUNCE_IDENTIFIER 0x0D

#ifdef AKES_CORESEC_STRATEGY_CONF_CUT_CHECKSUM
#define CUT_CHECKSUM AKES_CORESEC_STRATEGY_CONF_CUT_CHECKSUM
#else /* AKES_CORESEC_STRATEGY_CONF_CUT_CHECKSUM */
#define CUT_CHECKSUM 1
#endif /* AKES_CORESEC_STRATEGY_CONF_CUT_CHECKSUM */

/* Log configuration */
#include "sys/log.h"
#define LOG_MODULE "AKES-coresec"
#define LOG_LEVEL LOG_LEVEL_MAC

struct mic {
  uint8_t u8[AKES_MAC_BROADCAST_MIC_LEN];
};

#if LLSEC802154_USES_FRAME_COUNTER && AKES_NBR_WITH_PAIRWISE_KEYS && (!WITH_BROADCAST_ENCRYPTION || AKES_NBR_WITH_GROUP_KEYS)

static struct mic mics[MAX_BUFFERED_MICS];
static uint8_t next_mic_index;
static struct cmd_broker_subscription subscription;
#if ENERGEST_CONF_ON
rtimer_clock_t last_announce_txtime;
rtimer_clock_t last_announce_rxtime;
rtimer_clock_t last_announce_cputime;
#endif /* ENERGEST_CONF_ON */

/*---------------------------------------------------------------------------*/
/**
 * Payload format:
 * | 0x0d | 0x00 | CCM*-MIC for neighbor 0 | ... | CCM*-MIC for last neighbor |
 */
static void
prepare_announce(void)
{
  struct akes_nbr_entry *next;
  uint8_t announced_mics[NBR_TABLE_MAX_NEIGHBORS * AKES_MAC_BROADCAST_MIC_LEN];
  uint8_t *payload;
  uint8_t announced_mics_len;
  uint8_t max_index;
  uint8_t local_index;

  max_index = 0;
  next = akes_nbr_head();
  while(next) {
    if(next->permanent) {
      local_index = akes_nbr_index_of(next->permanent);
      akes_mac_aead(next->permanent->pairwise_key,
          0,
          announced_mics + (local_index * AKES_MAC_BROADCAST_MIC_LEN),
          1);
      if(local_index > max_index) {
        max_index = local_index;
      }
    }
    next = akes_nbr_next(next);
  }

  payload = akes_mac_prepare_command(ANNOUNCE_IDENTIFIER, &linkaddr_null);

  /* write payload */
  /* TODO We currently assume that all MICs fit within a single ANNOUNCE command */
  payload[0] = 0;
  announced_mics_len = (max_index + 1) * AKES_MAC_BROADCAST_MIC_LEN;
  memcpy(payload + 1, announced_mics, announced_mics_len);
  packetbuf_set_datalen(1 + 1 + announced_mics_len);
}
/*---------------------------------------------------------------------------*/
static void
on_announce_sent(void *ptr, int status, int transmissions)
{
  last_announce_txtime = packetbuf_get_rtimer_attr(PACKETBUF_ATTR_TXTIME);
  last_announce_rxtime = packetbuf_get_rtimer_attr(PACKETBUF_ATTR_RXTIME);
  last_announce_cputime = packetbuf_get_rtimer_attr(PACKETBUF_ATTR_CPUTIME);
}
/*---------------------------------------------------------------------------*/
static void
on_broadcast_sent(void *ptr, int status, int transmissions)
{
  packetbuf_set_rtimer_attr(PACKETBUF_ATTR_TXTIME, packetbuf_get_rtimer_attr(PACKETBUF_ATTR_TXTIME) + last_announce_txtime);
  packetbuf_set_rtimer_attr(PACKETBUF_ATTR_RXTIME, packetbuf_get_rtimer_attr(PACKETBUF_ATTR_RXTIME) + last_announce_rxtime);
  packetbuf_set_rtimer_attr(PACKETBUF_ATTR_CPUTIME, packetbuf_get_rtimer_attr(PACKETBUF_ATTR_CPUTIME) + last_announce_cputime);

  mac_call_sent_callback(ptr, NULL, status, transmissions);
}
/*---------------------------------------------------------------------------*/
static void
send_broadcast(mac_callback_t sent, void *ptr)
{
  struct queuebuf *qb;

#if ENERGEST_CONF_ON
  energest_flush();
  energest_type_set(ENERGEST_TYPE_CPU, 0);
#endif /* ENERGEST_CONF_ON */
  qb = queuebuf_new_from_packetbuf();
  packetbuf_set_addr(PACKETBUF_ADDR_SENDER, &linkaddr_node_addr);
  if(!qb || (NETSTACK_FRAMER.create() < 0)) {
    LOG_ERR("did not send broadcast\n");
    if(qb) {
      queuebuf_free(qb);
    }
    sent(ptr, MAC_TX_ERR, 0);
    return;
  }

#if CUT_CHECKSUM
  packetbuf_set_datalen(packetbuf_datalen() - CRC16_FRAMER_CHECKSUM_LEN);
#endif /* CUT_CHECKSUM */
  prepare_announce();
#if ENERGEST_CONF_ON
  packetbuf_set_rtimer_attr(PACKETBUF_ATTR_CPUTIME, energest_type_time(ENERGEST_TYPE_CPU));
  AKES_MAC_DECORATED_MAC.send(on_announce_sent, NULL);
#else /* ENERGEST_CONF_ON */
  akes_mac_send_command_frame();
#endif /* ENERGEST_CONF_ON */
  watchdog_periodic();

  queuebuf_to_packetbuf(qb);
  queuebuf_free(qb);
#if WITH_BROADCAST_ENCRYPTION
  {
    uint8_t ignore[AKES_MAC_BROADCAST_MIC_LEN];

    if(akes_mac_get_sec_lvl() & (1 << 2)) {
      akes_mac_aead(akes_mac_group_key, 1, ignore, 1);
    }
  }
#endif /* WITH_BROADCAST_ENCRYPTION */
#if ENERGEST_CONF_ON
  AKES_MAC_DECORATED_MAC.send(on_broadcast_sent, sent);
#else /* ENERGEST_CONF_ON */
  AKES_MAC_DECORATED_MAC.send(sent, ptr);
#endif /* ENERGEST_CONF_ON */
}
/*---------------------------------------------------------------------------*/
static void
send(mac_callback_t sent, void *ptr)
{
  if(packetbuf_holds_broadcast()) {
    send_broadcast(sent, ptr);
  } else {
    AKES_MAC_DECORATED_MAC.send(sent, ptr);
  }
}
/*---------------------------------------------------------------------------*/
static int
is_mic_stored(uint8_t *mic)
{
  uint8_t i;

  for(i = 0; i < MAX_BUFFERED_MICS; i++) {
    if(!memcmp(mic, mics[i].u8, AKES_MAC_BROADCAST_MIC_LEN)) {
      return 1;
    }
  }
  return 0;
}
/*---------------------------------------------------------------------------*/
static enum cmd_broker_result
on_command(uint8_t cmd_id, uint8_t *payload)
{
  struct akes_nbr_entry *entry;
  uint8_t *max_payload;

  if(cmd_id != ANNOUNCE_IDENTIFIER) {
    return CMD_BROKER_UNCONSUMED;
  }

  entry = akes_nbr_get_sender_entry();
  if(!entry || !entry->permanent) {
    return CMD_BROKER_ERROR;
  }

  LOG_INFO("received ANNOUNCE\n");

  /* calculate CCM*-MIC location */
  payload += 1 + (entry->permanent->foreign_index * AKES_MAC_BROADCAST_MIC_LEN);

  /* check if CCM*-MIC location is within ANNOUNCE */
  max_payload = ((uint8_t *)packetbuf_dataptr()) + packetbuf_datalen() - 1;
  if(payload + AKES_MAC_BROADCAST_MIC_LEN - 1 > max_payload) {
    LOG_ERR("out of bounds\n");
    return CMD_BROKER_ERROR;
  }

  /*
   * check if contained CCM*-MIC is already stored, e.g.,
   * due to duplicated ANNOUNCE
   */
  if(is_mic_stored(payload)) {
    LOG_WARN("already stored\n");
    return CMD_BROKER_ERROR;
  }

  /* store CCM*-MIC */
  memcpy(mics[next_mic_index].u8, payload, AKES_MAC_BROADCAST_MIC_LEN);
  if(++next_mic_index == MAX_BUFFERED_MICS) {
    next_mic_index = 0;
  }

  return CMD_BROKER_CONSUMED;
}
/*---------------------------------------------------------------------------*/
static int
on_frame_created(void)
{
  uint8_t sec_lvl;
  enum akes_nbr_status status;
  struct akes_nbr_entry *entry;
  uint8_t *dataptr;
  uint8_t datalen;

  sec_lvl = akes_mac_get_sec_lvl();
  if(sec_lvl && !packetbuf_holds_broadcast()) {
    status = akes_get_receiver_status();
    entry = akes_nbr_get_receiver_entry();

    if(!entry || !entry->refs[status]) {
      return 0;
    }

    dataptr = packetbuf_dataptr();
    datalen = packetbuf_datalen();

    akes_mac_aead(entry->refs[status]->pairwise_key,
        sec_lvl & (1 << 2),
        dataptr + datalen,
        1);
    packetbuf_set_datalen(datalen + AKES_MAC_UNICAST_MIC_LEN);
  }
  return 1;
}
/*---------------------------------------------------------------------------*/
static int
verify_broadcast(struct akes_nbr *sender)
{
  uint8_t mic[AKES_MAC_BROADCAST_MIC_LEN];

#if WITH_BROADCAST_ENCRYPTION
  akes_mac_aead(sender->group_key, akes_mac_get_sec_lvl() & (1 << 2), mic, 0);
#endif /* WITH_BROADCAST_ENCRYPTION */
  akes_mac_aead(sender->pairwise_key, 0, mic, 0);

  return !is_mic_stored(mic);
}
/*---------------------------------------------------------------------------*/
static enum akes_mac_verify
verify(struct akes_nbr *sender)
{
  if(packetbuf_holds_broadcast()) {
    if(verify_broadcast(sender)) {
      LOG_ERR("inauthentic broadcast\n");
      return AKES_MAC_VERIFY_INAUTHENTIC;
    }
  } else {
    if(akes_mac_verify(sender->pairwise_key)) {
      LOG_ERR("inauthentic unicast\n");
      return AKES_MAC_VERIFY_INAUTHENTIC;
    }
  }

  if(anti_replay_was_replayed(&sender->anti_replay_info)) {
    LOG_ERR("replayed\n");
    return AKES_MAC_VERIFY_REPLAYED;
  }

  return AKES_MAC_VERIFY_SUCCESS;
}
/*---------------------------------------------------------------------------*/
static uint8_t
get_overhead(void)
{
  return packetbuf_holds_broadcast() ? 0 : AKES_MAC_UNICAST_MIC_LEN;
}
/*---------------------------------------------------------------------------*/
static void
init(void)
{
  subscription.on_command = on_command;
  cmd_broker_subscribe(&subscription);
}
/*---------------------------------------------------------------------------*/
static uint8_t *
write_piggyback(uint8_t *data, uint8_t cmd_id, struct akes_nbr_entry *entry)
{
  return data;
}
/*---------------------------------------------------------------------------*/
static uint8_t *
read_piggyback(uint8_t *data,
    uint8_t cmd_id,
    struct akes_nbr_entry *entry,
    struct akes_nbr_tentative *meta)
{
  return data;
}
/*---------------------------------------------------------------------------*/
static int
before_create(void)
{
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
}
/*---------------------------------------------------------------------------*/
static void
on_fresh_authentic_helloack(void)
{
}
/*---------------------------------------------------------------------------*/
const struct akes_mac_strategy akes_coresec_strategy = {
  ccm_star_packetbuf_set_nonce,
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
#endif /* LLSEC802154_USES_FRAME_COUNTER && AKES_NBR_WITH_PAIRWISE_KEYS && (!WITH_BROADCAST_ENCRYPTION || AKES_NBR_WITH_GROUP_KEYS) */

/** @} */
