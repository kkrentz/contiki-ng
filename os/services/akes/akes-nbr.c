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
 *         Neighbor management.
 * \author
 *         Konrad Krentz <konrad.krentz@gmail.com>
 */

#include "akes/akes-nbr.h"
#include "akes/akes.h"
#include "lib/assert.h"
#include "lib/list.h"
#include "lib/memb.h"
#include "net/mac/framer/frame802154.h"
#include "net/mac/llsec802154.h"
#include "net/packetbuf.h"
#include "sys/mutex.h"
#include <string.h>

/* Log configuration */
#include "sys/log.h"
#define LOG_MODULE "AKES-nbr"
#define LOG_LEVEL LOG_LEVEL_MAC

#ifndef AKES_NBR_CONF_WITH_LOCKING
#define AKES_NBR_CONF_WITH_LOCKING (0)
#endif /* AKES_NBR_CONF_WITH_LOCKING */

NBR_TABLE(struct akes_nbr_entry, entries_table);
MEMB(nbrs_memb, struct akes_nbr, AKES_NBR_MAX);
MEMB(tentatives_memb, struct akes_nbr_tentative, AKES_NBR_MAX_TENTATIVES);
#if AKES_NBR_CONF_WITH_LOCKING
static mutex_t lock;
#endif /* AKES_NBR_CONF_WITH_LOCKING */

/*---------------------------------------------------------------------------*/
static bool
get_lock(void)
{
#if AKES_NBR_CONF_WITH_LOCKING
  return mutex_try_lock(&lock);
#else /* AKES_NBR_CONF_WITH_LOCKING */
  return true;
#endif /* AKES_NBR_CONF_WITH_LOCKING */
}
/*---------------------------------------------------------------------------*/
static void
release_lock(void)
{
#if AKES_NBR_CONF_WITH_LOCKING
  mutex_unlock(&lock);
#endif /* AKES_NBR_CONF_WITH_LOCKING */
}
/*---------------------------------------------------------------------------*/
bool
akes_nbr_can_query_asynchronously(void)
{
  if(!get_lock()) {
    return false;
  }
  release_lock();
  return true;
}
/*---------------------------------------------------------------------------*/
size_t
akes_nbr_index_of_tentative(const struct akes_nbr_tentative *tentative)
{
  return tentative - tentatives_memb_memb_mem;
}
/*---------------------------------------------------------------------------*/
size_t
akes_nbr_index_of(const struct akes_nbr *nbr)
{
  return nbr - (struct akes_nbr *)nbrs_memb.mem;
}
/*---------------------------------------------------------------------------*/
struct akes_nbr *
akes_nbr_get_nbr(uint8_t index)
{
  if(index >= AKES_NBR_MAX) {
    return NULL;
  }
  return &((struct akes_nbr *)nbrs_memb.mem)[index];
}
/*---------------------------------------------------------------------------*/
struct akes_nbr_entry *
akes_nbr_get_entry_of(struct akes_nbr *nbr)
{
  for(struct akes_nbr_entry *entry = nbr_table_head(entries_table);
      entry;
      entry = nbr_table_next(entries_table, entry)) {
    if((entry->tentative == nbr) || (entry->permanent == nbr)) {
      return entry;
    }
  }
  return NULL;
}
/*---------------------------------------------------------------------------*/
void
akes_nbr_free_tentative_metadata(struct akes_nbr_tentative *meta)
{
  memb_free(&tentatives_memb, meta);
}
/*---------------------------------------------------------------------------*/
void
akes_nbr_copy_challenge(uint8_t dest[static AKES_NBR_CHALLENGE_LEN],
    const uint8_t source[AKES_NBR_CHALLENGE_LEN])
{
  memcpy(dest, source, AKES_NBR_CHALLENGE_LEN);
}
/*---------------------------------------------------------------------------*/
void
akes_nbr_copy_key(uint8_t dest[static AES_128_KEY_LENGTH],
    const uint8_t source[static AES_128_KEY_LENGTH])
{
  memcpy(dest, source, AES_128_KEY_LENGTH);
}
/*---------------------------------------------------------------------------*/
const linkaddr_t *
akes_nbr_get_addr(const struct akes_nbr_entry *entry)
{
  return nbr_table_get_lladdr(entries_table, entry);
}
/*---------------------------------------------------------------------------*/
static void
on_entry_change(struct akes_nbr_entry *entry)
{
  if(!entry->permanent && !entry->tentative) {
    nbr_table_remove(entries_table, entry);
  }
}
/*---------------------------------------------------------------------------*/
struct akes_nbr_entry *
akes_nbr_head(enum akes_nbr_status status)
{
  struct akes_nbr_entry *entry;

  entry = nbr_table_head(entries_table);
  return !entry || entry->refs[status]
      ? entry
      : akes_nbr_next(entry, status);
}
/*---------------------------------------------------------------------------*/
struct akes_nbr_entry *
akes_nbr_next(struct akes_nbr_entry *entry, enum akes_nbr_status status)
{
  do {
    entry = nbr_table_next(entries_table, entry);
  } while(entry && !entry->refs[status]);
  return entry;
}
/*---------------------------------------------------------------------------*/
size_t
akes_nbr_count(enum akes_nbr_status status)
{
  size_t count = 0;
  for(struct akes_nbr_entry *entry = akes_nbr_head(status);
      entry;
      entry = akes_nbr_next(entry, status)) {
    count++;
  }
  return count;
}
/*---------------------------------------------------------------------------*/
size_t
akes_nbr_free_slots(void)
{
  return memb_numfree(&nbrs_memb);
}
/*---------------------------------------------------------------------------*/
static void
delete_nbr_with_lock(struct akes_nbr_entry *entry, enum akes_nbr_status status)
{
  assert(entry);
  if(status) {
    akes_nbr_free_tentative_metadata(entry->refs[status]->meta);
  }
  memb_free(&nbrs_memb, entry->refs[status]);
  entry->refs[status] = NULL;
  on_entry_change(entry);
}
/*---------------------------------------------------------------------------*/
struct akes_nbr_entry *
akes_nbr_new(enum akes_nbr_status status)
{
  if(status
      && (akes_nbr_count(AKES_NBR_TENTATIVE) >= AKES_NBR_MAX_TENTATIVES)) {
    LOG_WARN("too many tentative neighbors\n");
    return NULL;
  }

  struct akes_nbr_entry *entry = akes_nbr_get_sender_entry();
  if(!entry) {
    entry = nbr_table_add_lladdr(entries_table,
        packetbuf_addr(PACKETBUF_ADDR_SENDER),
        NBR_TABLE_REASON_LLSEC,
        NULL);
    if(!entry) {
      LOG_WARN("nbr-table is full\n");
      return NULL;
    }
  }

  while(!get_lock());
  entry->refs[status] = memb_alloc(&nbrs_memb);
  if(!entry->refs[status]) {
    LOG_WARN("RAM is running low\n");
    on_entry_change(entry);
    release_lock();
    return NULL;
  }
  nbr_table_lock(entries_table, entry);
#if LLSEC802154_USES_FRAME_COUNTER
  anti_replay_init_info(&entry->refs[status]->anti_replay_info);
#endif /* LLSEC802154_USES_FRAME_COUNTER */
  if(status) {
    entry->refs[status]->meta = memb_alloc(&tentatives_memb);
    if(!entry->refs[status]->meta) {
      LOG_WARN("tentatives_memb full\n");
      delete_nbr_with_lock(entry, status);
      release_lock();
      return NULL;
    }
  }
  release_lock();
  return entry;
}
/*---------------------------------------------------------------------------*/
struct akes_nbr *
akes_nbr_clone(struct akes_nbr *nbr)
{
  struct akes_nbr *clone;

  clone = memb_alloc(&nbrs_memb);
  if(!clone) {
    return NULL;
  }
  memcpy(clone, nbr, sizeof(*clone));
  return clone;
}
/*---------------------------------------------------------------------------*/
struct akes_nbr_entry *
akes_nbr_get_entry(const linkaddr_t *addr)
{
  return nbr_table_get_from_lladdr(entries_table, addr);
}
/*---------------------------------------------------------------------------*/
struct akes_nbr_entry *
akes_nbr_get_sender_entry(void)
{
  return akes_nbr_get_entry(packetbuf_addr(PACKETBUF_ADDR_SENDER));
}
/*---------------------------------------------------------------------------*/
struct akes_nbr_entry *
akes_nbr_get_receiver_entry(void)
{
  return akes_nbr_get_entry(packetbuf_addr(PACKETBUF_ADDR_RECEIVER));
}
/*---------------------------------------------------------------------------*/
void
akes_nbr_delete(struct akes_nbr_entry *entry, enum akes_nbr_status status)
{
  assert(!status
      || ctimer_expired(&entry->tentative->meta->wait_timer));
  LOG_INFO("deleting %s neighbor\n", status ? "tentative" : "permanent");
  while(!get_lock());
  delete_nbr_with_lock(entry, status);
  release_lock();
}
/*---------------------------------------------------------------------------*/
void
akes_nbr_init(void)
{
  memb_init(&nbrs_memb);
  nbr_table_register(entries_table, NULL);
  memb_init(&tentatives_memb);
}
/*---------------------------------------------------------------------------*/

/** @} */
