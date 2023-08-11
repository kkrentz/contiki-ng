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
 *         Clustered Neighborhood-aware Contention Resolution (CNCR).
 * \author
 *         Konrad Krentz <konrad.krentz@gmail.com>
 */

#include "cncr.h"
#include "lib/aes-128.h"
#include "net/mac/csl/csl.h"
#include "net/mac/frame-queue.h"
#include "net/mac/wake-up-counter.h"
#include "net/packetbuf.h"
#include "smor-db.h"
#include <stdbool.h>
#include <string.h>

/* Log configuration */
#include "sys/log.h"
#define LOG_MODULE "CNCR"
#define LOG_LEVEL LOG_LEVEL_RPL

union priority {
  uint8_t u8[AES_128_BLOCK_SIZE];
  uint32_t u32[AES_128_BLOCK_SIZE / sizeof(uint32_t)];
};

static smor_db_id_t ncr(smor_db_bitmap_t contenders,
    wake_up_counter_t contention_context);
static void compute_priority(union priority *priority,
    smor_db_id_t id,
    wake_up_counter_t contention_context);
static bool is_greater_than_or_equal(union priority *this,
    union priority *that);

static const uint8_t key[AES_128_KEY_LENGTH];

/*---------------------------------------------------------------------------*/
bool
cncr_can_access()
{
  const linkaddr_t *receiver_addr = packetbuf_addr(PACKETBUF_ADDR_RECEIVER);

  if(frame_queue_am_retrying(receiver_addr)) {
    return true;
  }

  smor_db_id_t receiver_id = smor_db_get_id(receiver_addr);
  if(receiver_id == SMOR_DB_INVALID_ID) {
    LOG_WARN("receiver has not become a neighbor, yet\n");
    return true;
  }

  smor_db_bitmap_t contenders = smor_db_get_adjacency_list(receiver_id);
  if(!(contenders & (1 << smor_db_my_id))) {
    LOG_WARN("apparently we are still bootstrapping\n");
    return true;
  }

  /* determine NCR winner */
  smor_db_id_t winner = ncr(contenders, csl_state.receivers_wake_up_counter);
  if(winner == smor_db_my_id) {
    return true;
  }
  LOG_DBG("winner of %u: ", csl_state.receivers_wake_up_counter.u32);
  LOG_DBG_LLADDR(smor_db_get_address(winner));
  LOG_DBG_("\n");
  if(!smor_db_have_link(smor_db_my_id, winner)) {
    /* we cannot become a member of the winner set */
    return false;
  }

  /* determine the winner set */
  smor_db_bitmap_t candidates = smor_db_get_adjacency_list(winner) & contenders;
  smor_db_bitmap_t winners_set = 1 << winner;
  const linkaddr_t *min_addr;
  while(candidates) {
    /* find out the next neighbor with the smallest MAC address */
    /* TODO pseudorandom */
    smor_db_id_t min_id = SMOR_DB_INVALID_ID;
    for(smor_db_id_t id = 0; id < SMOR_DB_MAX_NODES; id++) {
      if(!(candidates & (1 << id))) {
        continue;
      }
      const linkaddr_t *addr = smor_db_get_address(id);
      if((min_id == SMOR_DB_INVALID_ID)
          || linkaddr_smaller_or_equal(addr, min_addr)) {
        min_id = id;
        min_addr = addr;
      }
    }
    candidates &= ~(1 << min_id);

    /* find out if it is a neighbor of all winners */
    if(winners_set
        != (winners_set & smor_db_get_adjacency_list(min_id))) {
      return false;
    }
    winners_set |= 1 << min_id;
  }
  return winners_set & (1 << smor_db_my_id);
}
/*---------------------------------------------------------------------------*/
static smor_db_id_t
ncr(smor_db_bitmap_t contenders,
    wake_up_counter_t contention_context)
{
  union priority max_priority;
  union priority priority;

  smor_db_id_t max_contender = SMOR_DB_INVALID_ID;

  AES_128.get_lock();
  AES_128.set_key(key);

  for(smor_db_id_t id = 0; id < SMOR_DB_MAX_NODES; id++) {
    if(!(contenders & (1 << id))) {
      continue;
    }
    compute_priority(&priority, id, contention_context);
    if((max_contender == SMOR_DB_INVALID_ID)
        || is_greater_than_or_equal(&priority, &max_priority)) {
      max_contender = id;
      memcpy(max_priority.u8, priority.u8, AES_128_BLOCK_SIZE);
    }
  }

  AES_128.release_lock();

  return max_contender;
}
/*---------------------------------------------------------------------------*/
static void
compute_priority(union priority *priority,
    smor_db_id_t id,
    wake_up_counter_t contention_context)
{
  linkaddr_write(priority->u8, smor_db_get_address(id));
  wake_up_counter_write(priority->u8 + LINKADDR_SIZE, contention_context);
  memset(priority->u8 + LINKADDR_SIZE + WAKE_UP_COUNTER_LEN,
      0,
      AES_128_BLOCK_SIZE - LINKADDR_SIZE - WAKE_UP_COUNTER_LEN);
  AES_128.encrypt(priority->u8);
  /* no need to append linkaddr since AES is injective */
}
/*---------------------------------------------------------------------------*/
static bool
is_greater_than_or_equal(union priority *this, union priority *that)
{
  size_t i;

  for(i = 0; i < AES_128_BLOCK_SIZE / sizeof(uint32_t); i++) {
    if(this->u32[i] < that->u32[i]) {
      return false;
    }
    if(this->u32[i] > that->u32[i]) {
      return true;
    }
  }
  return true;
}
/*---------------------------------------------------------------------------*/
