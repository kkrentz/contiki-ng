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
 */

/**
 * \file
 *         Trickling of adjacency lists.
 * \author
 *         Konrad Krentz <konrad.krentz@gmail.com>
 */

#include "lib/assert.h"
#include "lib/leaky-bucket.h"
#include "lib/trickle.h"
#include "net/mac/cmd-broker.h"
#include "net/mac/wake-up-counter.h"
#include "net/nbr-table.h"
#include "net/netstack.h"
#include "net/packetbuf.h"
#include "net/queuebuf.h"
#include "services/akes/akes-mac.h"
#include "smor-db.h"
#include "smor-trickle.h"
#include <sys/types.h>

/* Log configuration */
#include "sys/log.h"
#define LOG_MODULE "SMOR-Trickle"
#define LOG_LEVEL LOG_LEVEL_RPL

#define CMD_FRAME_IDENTIFIER (0x0F)
#define HEADER_LEN (2)
#define CMD_FRAME_IDENTIFIER_LEN (1)
#define IMIN (30 * CLOCK_SECOND)
#define IMAX (8)
#define REDUNDANCY_CONSTANT (2)
#define MAX_CONSECUTIVE_BROADCASTS (10)
#define MAX_BROADCAST_RATE (200) /* 1 per 200s */

static void on_trickle_callback(void);
static void send(smor_db_id_t receiver_id);
static void on_command_sent(void *ptr, int status, int transmissions);
static cmd_broker_result_t on_command(uint8_t cmd_id, uint8_t *payload);
static void on_consistent_unicast(smor_db_id_t sender_id);
void on_inconsistent_unicast(void);

static cmd_broker_subscription_t subscription = { NULL , on_command };
static struct trickle trickle;
static leaky_bucket_t broadcast_bucket;
static smor_db_bitmap_t trickle_incrementers_bitmap;
PROCESS(smor_tickle_broadcast_process, "smor_tickle_broadcast_process");

/*---------------------------------------------------------------------------*/
void
smor_trickle_init(void)
{
  cmd_broker_subscribe(&subscription);
  trickle_start(&trickle,
      IMIN,
      IMAX,
      REDUNDANCY_CONSTANT,
      on_trickle_callback,
      NULL);
  leaky_bucket_init(&broadcast_bucket,
      MAX_CONSECUTIVE_BROADCASTS,
      MAX_BROADCAST_RATE);
}
/*---------------------------------------------------------------------------*/
static void
on_trickle_callback(void)
{
  if(process_is_running(&smor_tickle_broadcast_process)) {
    return;
  }
  if(leaky_bucket_is_full(&broadcast_bucket)) {
    LOG_WARN("leaky bucket counter is full\n");
    return;
  }
  leaky_bucket_pour(&broadcast_bucket);
  trickle_incrementers_bitmap = 0;
  process_start(&smor_tickle_broadcast_process, NULL);
}
/*---------------------------------------------------------------------------*/
PROCESS_THREAD(smor_tickle_broadcast_process, ev, data)
{
  static smor_db_bitmap_t unicasted_neighbors_bitmap;
  static struct etimer timer;
  smor_db_id_t i;

  PROCESS_BEGIN();

  unicasted_neighbors_bitmap = 0;
  do {
    while(!queuebuf_numfree()) {
      etimer_set(&timer, CLOCK_SECOND / WAKE_UP_COUNTER_RATE);
      PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&timer));
    }
    for(i = 0; i < SMOR_DB_MAX_NODES; i++) {
      if((i != smor_db_my_id)
          && smor_db_have_link(i, smor_db_my_id)
          && !(unicasted_neighbors_bitmap & (1 << i))) {
        unicasted_neighbors_bitmap |= 1 << i;
        send(i);
        if(!queuebuf_numfree()) {
          break;
        }
      }
    }
  } while(i < SMOR_DB_MAX_NODES);

  PROCESS_END();
}
/*---------------------------------------------------------------------------*/
static void
send(smor_db_id_t receiver_id)
{
  uint8_t *header = cmd_broker_prepare_command(CMD_FRAME_IDENTIFIER,
      smor_db_get_address(receiver_id));
  int space = NETSTACK_MAC.max_payload()
      - CMD_FRAME_IDENTIFIER_LEN
      - HEADER_LEN;
  if(space < 0) {
    LOG_ERR("went out of space at line %d\n", __LINE__);
    return;
  }
  memset(header, 0, HEADER_LEN);
  uint8_t *payload = header + HEADER_LEN;
  akes_mac_set_numbers(NULL);
  for(smor_db_id_t i = 0; i < SMOR_DB_MAX_NODES; i++) {
    if((i != smor_db_my_id)
        && (i != receiver_id)
        && smor_db_have_link(i, receiver_id)) {
      space -= LINKADDR_SIZE;
      if(space < 0) {
        LOG_ERR("went out of space at line %d\n", __LINE__);
        return;
      }
      linkaddr_write(payload, smor_db_get_address(i));
      header[0]++;
      payload += LINKADDR_SIZE;
    }
  }
  for(smor_db_id_t i = 0; i < SMOR_DB_MAX_NODES; i++) {
    if((i != smor_db_my_id)
        && (i != receiver_id)
        && smor_db_have_link(i, smor_db_my_id)) {
      space -= LINKADDR_SIZE;
      if(space < 0) {
        LOG_ERR("went out of space at line %d\n", __LINE__);
        return;
      }
      linkaddr_write(payload, smor_db_get_address(i));
      header[1]++;
      payload += LINKADDR_SIZE;
    }
  }
  packetbuf_set_datalen((payload - header) + CMD_FRAME_IDENTIFIER_LEN);
  AKES_MAC_STRATEGY.send(on_command_sent, NULL);
}
/*---------------------------------------------------------------------------*/
static void
on_command_sent(void *ptr, int status, int transmissions)
{
  if(status == MAC_TX_DEFERRED) {
    /* we expect another callback at a later point in time */
    return;
  }
  /* TODO retransmit if status == MAC_TX_QUEUE_FULL */
  akes_mac_report_to_network_layer(status, transmissions);
}
/*---------------------------------------------------------------------------*/
static cmd_broker_result_t
on_command(uint8_t cmd_id, uint8_t *header)
{
  if(cmd_id != CMD_FRAME_IDENTIFIER) {
    return CMD_BROKER_UNCONSUMED;
  }
  if(!akes_mac_check_frame()) {
    return CMD_BROKER_CONSUMED;
  }
  const linkaddr_t *sender_addr = packetbuf_addr(PACKETBUF_ADDR_SENDER);
  LOG_INFO("received Trickle broadcast from ");
  LOG_INFO_LLADDR(sender_addr);
  LOG_INFO_("\n");

  /* check length */
  size_t length = packetbuf_datalen() - 1 /* command frame identifier */;
  if((length < HEADER_LEN)
      || ((length - HEADER_LEN)
          != ((header[0] + header[1]) * LINKADDR_SIZE))) {
    LOG_ERR("length is invalid %zu %u\n", length , (header[0] + header[1]) * LINKADDR_SIZE);
    goto exit;
  }

  /* set up pointers to adjacency lists */
  uint8_t *adjacency_list1 = header + HEADER_LEN;
  uint8_t *adjacency_list2 = adjacency_list1 + (LINKADDR_SIZE * header[0]);

  /* check second adjacency list first */
  smor_db_id_t sender_id = smor_db_get_id(sender_addr);
  if(sender_id == SMOR_DB_INVALID_ID) {
    LOG_ERR("smor_db_get_id failed\n");
    goto exit;
  }
  smor_db_bitmap_t received_adjacency_list_of_sender = 1 << smor_db_my_id;
  while(header[1]--) {
    linkaddr_t addr;
    linkaddr_read(&addr, adjacency_list2);
    smor_db_id_t neighbors_neighbor_id = smor_db_get_or_create_id(&addr);
    if(neighbors_neighbor_id == SMOR_DB_INVALID_ID) {
      LOG_WARN("smor_db_get_or_create_id failed\n");
    } else {
      received_adjacency_list_of_sender |= 1 << neighbors_neighbor_id;
    }
    adjacency_list2 += LINKADDR_SIZE;
  }
  if(received_adjacency_list_of_sender !=
      smor_db_get_adjacency_list(sender_id)) {
    smor_db_set_links(sender_id, received_adjacency_list_of_sender);
    LOG_DBG("second adjacency list differs\n");
    on_inconsistent_unicast();
    goto exit;
  }

  /* check first adjacency list for inconsistencies */
  smor_db_bitmap_t received_adjacency_list_of_mine = 1 << sender_id;
  while(header[0]--) {
    linkaddr_t addr;
    linkaddr_read(&addr, adjacency_list1);
    smor_db_id_t id = smor_db_get_id(&addr);
    if(id == SMOR_DB_INVALID_ID) {
      LOG_WARN("smor_db_get_id failed\n");
    } else {
      received_adjacency_list_of_mine |= 1 << id;
    }
    adjacency_list1 += LINKADDR_SIZE;
  }
  if(received_adjacency_list_of_mine !=
      smor_db_get_adjacency_list(smor_db_my_id)) {
    LOG_DBG("first adjacency list differs\n");
    on_inconsistent_unicast();
    goto exit;
  }

  on_consistent_unicast(sender_id);
exit:
  return CMD_BROKER_CONSUMED;
}
/*---------------------------------------------------------------------------*/
void
smor_trickle_on_new_neighbor(struct akes_nbr_entry *entry)
{
  trickle_incrementers_bitmap = SMOR_DB_BITMAP_MAX;
  trickle_reset(&trickle);
}
/*---------------------------------------------------------------------------*/
void
smor_trickle_on_neighbor_lost(struct akes_nbr_entry *entry)
{
  trickle_incrementers_bitmap = SMOR_DB_BITMAP_MAX;
  trickle_reset(&trickle);
}
/*---------------------------------------------------------------------------*/
static void
on_consistent_unicast(smor_db_id_t sender_id)
{
  LOG_INFO("on_consistent_unicast\n");
  smor_db_bitmap_t mask = 1 << sender_id;
  if(!(trickle_incrementers_bitmap & mask)) {
    trickle_incrementers_bitmap |= mask;
    trickle_increment_counter(&trickle);
  }
}
/*---------------------------------------------------------------------------*/
void
on_inconsistent_unicast(void)
{
  LOG_INFO("on_inconsistent_unicast\n");
  trickle_reset(&trickle);
}
/*---------------------------------------------------------------------------*/
