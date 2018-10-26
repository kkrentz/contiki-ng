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
 * \file
 *         Autoconfigures ContikiMAC
 * \author
 *         Konrad Krentz <konrad.krentz@gmail.com>
 */

/* configure Contiki */
#define FRAME802154_CONF_VERSION 0x02
#define SICSLOWPAN_CONF_MAC_MAX_PAYLOAD 127

/* configure AKES */
#ifndef AKES_MAC_CONF_ENABLED
#define AKES_MAC_CONF_ENABLED 1
#endif /* AKES_MAC_CONF_ENABLED */

#if AKES_MAC_CONF_ENABLED
#define AES_128_CONF_WITH_LOCKING 1
#define NBR_TABLE_CONF_WITH_LOCKING 1
#define AKES_NBR_CONF_WITH_LOCKING 1
#define NBR_TABLE_CONF_WITH_FIND_REMOVABLE 0
#define CSPRNG_CONF_ENABLED 1
#define NETSTACK_CONF_MAC akes_mac_driver
#define AKES_MAC_CONF_DECORATED_MAC contikimac_driver
#else /* AKES_MAC_CONF_ENABLED */
#define NETSTACK_CONF_MAC contikimac_driver
#endif /* AKES_MAC_CONF_ENABLED */

/* configure POTR */
#ifndef CONTIKIMAC_FRAMER_POTR_CONF_ENABLED
#define CONTIKIMAC_FRAMER_POTR_CONF_ENABLED AKES_MAC_CONF_ENABLED
#endif /* CONTIKIMAC_FRAMER_POTR_CONF_ENABLED */

#if CONTIKIMAC_FRAMER_POTR_CONF_ENABLED
#define AKES_DELETE_CONF_STRATEGY contikimac_strategy_delete
#define AKES_MAC_CONF_STRATEGY contikimac_strategy
#define AKES_NBR_CONF_WITH_GROUP_KEYS 1
#define PACKETBUF_CONF_WITH_UNENCRYPTED_BYTES 1
#define AKES_NBR_CONF_WITH_SEQNOS 1
#define AKES_NBR_CONF_CACHE_HELLOACK_CHALLENGE 0
#define NETSTACK_CONF_FRAMER akes_mac_framer
#define AKES_MAC_CONF_DECORATED_FRAMER contikimac_framer_potr
#elif AKES_MAC_CONF_ENABLED
#define NETSTACK_CONF_FRAMER crc16_framer
#define CRC16_FRAMER_CONF_DECORATED_FRAMER akes_mac_framer
#define AKES_MAC_CONF_DECORATED_FRAMER contikimac_framer_original
#define FRAME802154E_CONF_WITH_PADDING_IE 1
#include "os/services/akes/akes-strategy-autoconf.h"
#else /* AKES_MAC_CONF_ENABLED */
#define NETSTACK_CONF_FRAMER crc16_framer
#define CRC16_FRAMER_CONF_DECORATED_FRAMER contikimac_framer_original
#define FRAME802154E_CONF_WITH_PADDING_IE 1
#endif /* AKES_MAC_CONF_ENABLED */

/* configure SPLO */
#ifndef CONTIKIMAC_CONF_WITH_SECURE_PHASE_LOCK
#define CONTIKIMAC_CONF_WITH_SECURE_PHASE_LOCK CONTIKIMAC_FRAMER_POTR_CONF_ENABLED
#endif /* CONTIKIMAC_CONF_WITH_SECURE_PHASE_LOCK */
#define AKES_MAC_CONF_UNSECURE_UNICASTS !CONTIKIMAC_CONF_WITH_SECURE_PHASE_LOCK
#define AKES_NBR_CONF_WITH_EXPIRATION_TIME !CONTIKIMAC_CONF_WITH_SECURE_PHASE_LOCK

/* configure ILOS */
#ifndef CONTIKIMAC_FRAMER_POTR_ILOS_CONF_ENABLED
#define CONTIKIMAC_FRAMER_POTR_ILOS_CONF_ENABLED CONTIKIMAC_FRAMER_POTR_CONF_ENABLED
#endif /* CONTIKIMAC_FRAMER_POTR_ILOS_CONF_ENABLED */
#if !CONTIKIMAC_FRAMER_POTR_CONF_ENABLED && CONTIKIMAC_FRAMER_POTR_ILOS_CONF_ENABLED
#error forbidden config
#endif
#define LLSEC802154_CONF_USES_FRAME_COUNTER !CONTIKIMAC_FRAMER_POTR_ILOS_CONF_ENABLED
#define LLSEC802154_CONF_USES_AUX_HEADER (AKES_MAC_CONF_ENABLED && !CONTIKIMAC_FRAMER_POTR_CONF_ENABLED)
#ifndef ANTI_REPLAY_CONF_WITH_SUPPRESSION
#define ANTI_REPLAY_CONF_WITH_SUPPRESSION (CONTIKIMAC_CONF_WITH_SECURE_PHASE_LOCK && !CONTIKIMAC_FRAMER_POTR_ILOS_CONF_ENABLED)
#endif /* ANTI_REPLAY_CONF_WITH_SUPPRESSION */
