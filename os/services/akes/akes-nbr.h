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

#ifndef AKES_NBR_H_
#define AKES_NBR_H_

#include "contiki.h"
#include "lib/aes-128.h"
#include "net/linkaddr.h"
#include "net/mac/anti-replay.h"
#include "net/mac/llsec802154.h"
#include "net/nbr-table.h"
#include "sys/clock.h"
#include "sys/ctimer.h"
#include <stdbool.h>
#include <stdlib.h>

#ifdef AKES_NBR_CONF_LIFETIME
#define AKES_NBR_LIFETIME AKES_NBR_CONF_LIFETIME
#else /* AKES_NBR_CONF_LIFETIME */
#define AKES_NBR_LIFETIME (60 * 5) /* seconds */
#endif /* AKES_NBR_CONF_LIFETIME */

#ifdef AKES_NBR_CONF_MAX_TENTATIVES
#define AKES_NBR_MAX_TENTATIVES AKES_NBR_CONF_MAX_TENTATIVES
#else /* AKES_NBR_CONF_MAX_TENTATIVES */
#define AKES_NBR_MAX_TENTATIVES (5)
#endif /* AKES_NBR_CONF_MAX_TENTATIVES */

#ifdef AKES_NBR_CONF_MAX
#define AKES_NBR_MAX AKES_NBR_CONF_MAX
#else /* AKES_NBR_CONF_MAX */
#define AKES_NBR_MAX (NBR_TABLE_MAX_NEIGHBORS + 1)
#endif /* AKES_NBR_CONF_MAX */

#ifdef AKES_NBR_CONF_WITH_PAIRWISE_KEYS
#define AKES_NBR_WITH_PAIRWISE_KEYS AKES_NBR_CONF_WITH_PAIRWISE_KEYS
#else /* AKES_NBR_CONF_WITH_PAIRWISE_KEYS */
#define AKES_NBR_WITH_PAIRWISE_KEYS (0)
#endif /* AKES_NBR_CONF_WITH_PAIRWISE_KEYS */

#ifdef AKES_NBR_CONF_WITH_GROUP_KEYS
#define AKES_NBR_WITH_GROUP_KEYS AKES_NBR_CONF_WITH_GROUP_KEYS
#else /* AKES_NBR_CONF_WITH_GROUP_KEYS */
#define AKES_NBR_WITH_GROUP_KEYS (1)
#endif /* AKES_NBR_CONF_WITH_GROUP_KEYS */

#ifdef AKES_NBR_CONF_WITH_INDICES
#define AKES_NBR_WITH_INDICES AKES_NBR_CONF_WITH_INDICES
#else /* AKES_NBR_CONF_WITH_INDICES */
#define AKES_NBR_WITH_INDICES (0)
#endif /* AKES_NBR_CONF_WITH_INDICES */

#ifdef AKES_NBR_CONF_WITH_SEQNOS
#define AKES_NBR_WITH_SEQNOS AKES_NBR_CONF_WITH_SEQNOS
#else /* AKES_NBR_CONF_WITH_SEQNOS */
#define AKES_NBR_WITH_SEQNOS (0)
#endif /* AKES_NBR_CONF_WITH_SEQNOS */

#ifdef AKES_NBR_CONF_SEQNO_LIFETIME
#define AKES_NBR_SEQNO_LIFETIME AKES_NBR_CONF_SEQNO_LIFETIME
#else /* AKES_NBR_CONF_SEQNO_LIFETIME */
#define AKES_NBR_SEQNO_LIFETIME (20) /* seconds */
#endif /* AKES_NBR_CONF_SEQNO_LIFETIME */

#ifdef AKES_NBR_CONF_WITH_PROLONGATION_TIME
#define AKES_NBR_WITH_PROLONGATION_TIME AKES_NBR_CONF_WITH_PROLONGATION_TIME
#else /* AKES_NBR_CONF_WITH_PROLONGATION_TIME */
#ifdef AKES_DELETE_CONF_STRATEGY
#define AKES_NBR_WITH_PROLONGATION_TIME (0)
#else /* AKES_DELETE_CONF_STRATEGY */
#define AKES_NBR_WITH_PROLONGATION_TIME (1)
#endif /* AKES_DELETE_CONF_STRATEGY */
#endif /* AKES_NBR_CONF_WITH_PROLONGATION_TIME */

#ifdef AKES_NBR_CONF_CACHE_HELLOACK_CHALLENGE
#define AKES_NBR_CACHE_HELLOACK_CHALLENGE \
    AKES_NBR_CONF_CACHE_HELLOACK_CHALLENGE
#else /* AKES_NBR_CONF_CACHE_HELLOACK_CHALLENGE */
#define AKES_NBR_CACHE_HELLOACK_CHALLENGE !AKES_NBR_WITH_PAIRWISE_KEYS
#endif /* AKES_NBR_CONF_CACHE_HELLOACK_CHALLENGE */

#define AKES_NBR_CHALLENGE_LEN (AES_128_BLOCK_SIZE / 2)
#define AKES_NBR_CACHED_HELLOACK_CHALLENGE_LEN (2)
#define AKES_NBR_UNINITIALIZED_DRIFT INT32_MIN

enum akes_nbr_status {
  AKES_NBR_PERMANENT = 0,
  AKES_NBR_TENTATIVE = 1
};

struct akes_nbr_entry {
  union {
    struct akes_nbr *refs[2];
    struct {
      struct akes_nbr *permanent;
      struct akes_nbr *tentative;
    };
  };
};

struct akes_nbr_tentative {
  struct ctimer wait_timer;
  bool was_helloack_sent;
  bool was_cloned;
  uint8_t helloack_transmissions;
};

struct akes_nbr {
#if LLSEC802154_USES_FRAME_COUNTER
  struct anti_replay_info anti_replay_info;
#endif /* LLSEC802154_USES_FRAME_COUNTER */

  union {
    /* permanent */
    struct {
#if AKES_NBR_WITH_PAIRWISE_KEYS
      uint8_t pairwise_key[AES_128_KEY_LENGTH];
#endif /* AKES_NBR_WITH_PAIRWISE_KEYS */
#if AKES_NBR_WITH_GROUP_KEYS
      uint8_t group_key[AES_128_KEY_LENGTH];
#endif /* AKES_NBR_WITH_GROUP_KEYS */
#if AKES_NBR_WITH_PROLONGATION_TIME
      uint16_t prolongation_time;
#endif /* AKES_NBR_WITH_PROLONGATION_TIME */
#if AKES_NBR_CACHE_HELLOACK_CHALLENGE
      uint8_t helloack_challenge[AKES_NBR_CACHED_HELLOACK_CHALLENGE_LEN];
#endif /* AKES_NBR_CACHE_HELLOACK_CHALLENGE */
#if AKES_NBR_WITH_INDICES
      uint8_t foreign_index;
#endif /* AKES_NBR_WITH_INDICES */
#if AKES_NBR_WITH_SEQNOS
      uint8_t seqno;
      uint8_t seqno_timestamp;
      bool has_active_seqno:1;
#endif /* AKES_NBR_WITH_SEQNOS */
      bool sent_authentic_hello:1;
      bool is_receiving_update:1;
    };

    /* tentative */
    struct {
      union {
        uint8_t challenge[AKES_NBR_CHALLENGE_LEN];
        uint8_t tentative_pairwise_key[AES_128_KEY_LENGTH];
      };
      struct akes_nbr_tentative *meta;
    };
  };
};

/**
 * \brief Tells if internal modifications are ongoing
 */
bool akes_nbr_can_query_asynchronously(void);

/**
 * \brief Provides the index of a tentative neighbor
 */
size_t akes_nbr_index_of_tentative(
    const struct akes_nbr_tentative *tentative);

/**
 * \brief Provides the index of a neighbor
 */
size_t akes_nbr_index_of(const struct akes_nbr *nbr);

/**
 * \brief Returns the neighbor with the given index
 */
struct akes_nbr *akes_nbr_get_nbr(size_t index);

/**
 * \brief Retrieves the entry of a given neighbor
 */
struct akes_nbr_entry *akes_nbr_get_entry_of(struct akes_nbr *nbr);

/**
 * \brief Frees metadata of tentative neighbors
 */
void akes_nbr_free_tentative_metadata(struct akes_nbr_tentative *meta);

/**
 * \brief Copies an 8-byte challenge
 */
void akes_nbr_copy_challenge(uint8_t dest[static AKES_NBR_CHALLENGE_LEN],
    const uint8_t source[AKES_NBR_CHALLENGE_LEN]);

/**
 * \brief Copies a 16-byte key
 */
void akes_nbr_copy_key(uint8_t dest[static AES_128_KEY_LENGTH],
    const uint8_t source[static AES_128_KEY_LENGTH]);

/**
 * \brief Returns the MAC address of the neighbor with the given entry
 */
const linkaddr_t *akes_nbr_get_addr(const struct akes_nbr_entry *entry);

/**
 * \brief Returns the first neighbor with the given status
 */
struct akes_nbr_entry *akes_nbr_head(enum akes_nbr_status status);

/**
 * \brief Returns the next neighbor with the given status
 */
struct akes_nbr_entry *akes_nbr_next(struct akes_nbr_entry *current,
    enum akes_nbr_status status);

/**
 * \brief Provides the overall number of neighbors with the given status
 */
size_t akes_nbr_count(enum akes_nbr_status status);

/**
 * \brief Provides the number of available slots for storing new neighbors
 */
size_t akes_nbr_free_slots(void);

/**
 * \brief Creates a new neighbor with the given status
 */
struct akes_nbr_entry *akes_nbr_new(enum akes_nbr_status status);

/**
 * \brief Clones a neighbor
 */
struct akes_nbr *akes_nbr_clone(struct akes_nbr *nbr);

/**
 * \brief Searches a neighbor with the given MAC address
 */
struct akes_nbr_entry *akes_nbr_get_entry(const linkaddr_t *addr);

/**
 * \brief Searches a neighbor with the source address of the packetbuf
 */
struct akes_nbr_entry *akes_nbr_get_sender_entry(void);

/**
 * \brief Searches a neighbor with the destination address of the packetbuf
 */
struct akes_nbr_entry *akes_nbr_get_receiver_entry(void);

/**
 * \brief Deletes a tentative or permanent neighbor
 */
void akes_nbr_delete(struct akes_nbr_entry *entry,
    enum akes_nbr_status status);

/**
 * \brief Initializes
 */
void akes_nbr_init(void);

#endif /* AKES_NBR_H_ */

/** @} */
