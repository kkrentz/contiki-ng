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
 * \ingroup link-layer
 * \defgroup akes AKES
 * \brief The Adaptive Key Establishment Scheme (AKES).
 *
 * AKES establishes group or pairwise session keys based on predistributed
 * keying material. The underlying key predistribution scheme is replaceable.
 * @{
 *
 * \file
 *         Realizes AKES' three-way handshake.
 * \author
 *         Konrad Krentz <konrad.krentz@gmail.com>
 */

#ifndef AKES_H_
#define AKES_H_

#include "contiki.h"
#include "akes/akes-delete.h"
#include "akes/akes-mac.h"
#include "akes/akes-nbr.h"
#include <stdbool.h>

#ifdef AKES_CONF_MAX_WAITING_PERIOD
#define AKES_MAX_WAITING_PERIOD AKES_CONF_MAX_WAITING_PERIOD
#else /* AKES_CONF_MAX_WAITING_PERIOD */
#define AKES_MAX_WAITING_PERIOD (15) /* seconds */
#endif /* AKES_CONF_MAX_WAITING_PERIOD */

/* Defines the plugged-in scheme */
#ifdef AKES_CONF_SCHEME
#define AKES_SCHEME AKES_CONF_SCHEME
#else /* AKES_CONF_SCHEME */
#define AKES_SCHEME akes_single_scheme
#endif /* AKES_CONF_SCHEME */

#if AKES_NBR_WITH_GROUP_KEYS
#define AKES_ACKS_SEC_LVL (AKES_MAC_UNICAST_SEC_LVL | (1 << 2))
#else /* AKES_NBR_WITH_GROUP_KEYS */
#define AKES_ACKS_SEC_LVL (AKES_MAC_UNICAST_SEC_LVL & 3)
#endif /* AKES_NBR_WITH_GROUP_KEYS */

#define AKES_UPDATES_SEC_LVL (AKES_MAC_UNICAST_SEC_LVL & 3)
#define AKES_HELLO_PIGGYBACK_OFFSET \
  (1 /* command frame identifier */ \
   + AKES_NBR_CHALLENGE_LEN /* challenge */)
#define AKES_HELLO_DATALEN AKES_HELLO_PIGGYBACK_OFFSET
#define AKES_HELLOACK_PIGGYBACK_OFFSET \
  (1 /* command frame identifier */ \
   + AKES_NBR_CHALLENGE_LEN /* challenge */ \
   + (AKES_NBR_WITH_INDICES ? 1 : 0))
#define AKES_HELLOACK_DATALEN \
  (AKES_HELLOACK_PIGGYBACK_OFFSET \
   + (AKES_NBR_WITH_GROUP_KEYS ? AES_128_KEY_LENGTH : 0) \
   + AKES_MAC_UNICAST_MIC_LEN)
#define AKES_ACK_PIGGYBACK_OFFSET \
  (1 /* command frame identifier */ \
   + (AKES_NBR_WITH_INDICES ? 1 : 0))
#define AKES_ACK_DATALEN \
  (AKES_ACK_PIGGYBACK_OFFSET \
   + (AKES_NBR_WITH_GROUP_KEYS ? AES_128_KEY_LENGTH : 0) \
   + AKES_MAC_UNICAST_MIC_LEN)

/* Command frame identifiers */
enum {
  AKES_HELLO_IDENTIFIER = 0x0A,
  AKES_HELLOACK_IDENTIFIER = 0x0B,
  AKES_HELLOACK_P_IDENTIFIER = 0x1B,
  AKES_ACK_IDENTIFIER = 0x0C,
  AKES_UPDATE_IDENTIFIER = 0x0E,
};

/**
 * Structure of a pluggable scheme
 */
struct akes_scheme {

  /** Called at startup */
  void (* init)(void);

  /**
   * \return      Shared secret of length AES_128_KEY_LENGTH
   * \retval NULL HELLO shall be discarded
   */
  const uint8_t *(* get_secret_with_hello_sender)(const linkaddr_t *addr);

  /**
   * \return      Shared secret of length AES_128_KEY_LENGTH
   * \retval NULL HELLOACK shall be discarded
   */
  const uint8_t *(* get_secret_with_helloack_sender)(const linkaddr_t *addr);
};

extern const struct akes_scheme AKES_SCHEME;

/**
 * \brief Returns our current challenge that is inserted into HELLOs
 */
uint8_t *akes_get_hello_challenge(void);

/**
 * \brief Broadcasts a HELLO
 */
void akes_broadcast_hello(void);

/**
 * \brief Checks whether a received HELLO is valid
 */
bool akes_is_acceptable_hello(void);

/**
 * \brief Checks whether a received HELLOACK is valid
 */
bool akes_is_acceptable_helloack(void);

/**
 * \brief Checks whether a received ACK is valid
 */
bool akes_is_acceptable_ack(const akes_nbr_entry_t *entry);

/**
 * \brief Initializes
 */
void akes_init(void);

/**
 * \brief       Sends an UPDATE
 * \param entry The receiver's entry
 */
void akes_send_update(akes_nbr_entry_t *entry);

/**
 * \brief Tells whether the receiver is tentative or permanent
 */
akes_nbr_status_t akes_get_receiver_status(void);

#endif /* AKES_H_ */

/** @} */
