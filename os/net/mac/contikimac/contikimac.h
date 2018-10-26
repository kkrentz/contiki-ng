/*
 * Copyright (c) 2016, Hasso-Plattner-Institut.
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
 *         A denial-of-sleep-resilient version of ContikiMAC.
 * \author
 *         Konrad Krentz <konrad.krentz@gmail.com>
 */

#ifndef CONTIKIMAC_H_
#define CONTIKIMAC_H_

#include "net/mac/mac.h"
#include "sys/rtimer.h"
#include "net/netstack.h"
#include "net/mac/wake-up-counter.h"
#include "services/akes/akes-mac.h"
#include "net/packetbuf.h"
#include "net/mac/contikimac/contikimac-framer.h"
#include "net/mac/contikimac/contikimac-framer-original.h"
#include "net/mac/contikimac/contikimac-framer-potr.h"
#include "net/mac/anti-replay.h"
#include "dev/radio.h"
#ifdef LPM_CONF_ENABLE
#include "lpm.h"
#endif /* LPM_CONF_ENABLE */

#if CONTIKIMAC_FRAMER_POTR_ENABLED
#define CONTIKIMAC_FRAMER contikimac_framer_potr_contikimac_framer
#else /* CONTIKIMAC_FRAMER_POTR_ENABLED */
#define CONTIKIMAC_FRAMER contikimac_framer_original_contikimac_framer
#endif /* CONTIKIMAC_FRAMER_POTR_ENABLED */

#ifdef CONTIKIMAC_CONF_MIN_FRAME_LENGTH
#define CONTIKIMAC_MIN_FRAME_LENGTH CONTIKIMAC_CONF_MIN_FRAME_LENGTH
#else /* CONTIKIMAC_CONF_MIN_FRAME_LENGTH */
#define CONTIKIMAC_MIN_FRAME_LENGTH 34
#endif /* CONTIKIMAC_CONF_MIN_FRAME_LENGTH */

#ifdef CONTIKIMAC_CONF_WITH_INTRA_COLLISION_AVOIDANCE
#define CONTIKIMAC_WITH_INTRA_COLLISION_AVOIDANCE CONTIKIMAC_CONF_WITH_INTRA_COLLISION_AVOIDANCE
#else /* CONTIKIMAC_CONF_WITH_INTRA_COLLISION_AVOIDANCE */
#define CONTIKIMAC_WITH_INTRA_COLLISION_AVOIDANCE 1
#endif /* CONTIKIMAC_CONF_WITH_INTRA_COLLISION_AVOIDANCE */

#ifdef CONTIKIMAC_CONF_WITH_INTER_COLLISION_AVOIDANCE
#define CONTIKIMAC_WITH_INTER_COLLISION_AVOIDANCE CONTIKIMAC_CONF_WITH_INTER_COLLISION_AVOIDANCE
#else /* CONTIKIMAC_CONF_WITH_INTER_COLLISION_AVOIDANCE */
#define CONTIKIMAC_WITH_INTER_COLLISION_AVOIDANCE 0
#endif /* CONTIKIMAC_CONF_WITH_INTER_COLLISION_AVOIDANCE */

#if !CONTIKIMAC_FRAMER_POTR_ENABLED
#define CONTIKIMAC_WITH_SECURE_PHASE_LOCK 0
#else /* !CONTIKIMAC_FRAMER_POTR_ENABLED */
#ifdef CONTIKIMAC_CONF_WITH_SECURE_PHASE_LOCK
#define CONTIKIMAC_WITH_SECURE_PHASE_LOCK CONTIKIMAC_CONF_WITH_SECURE_PHASE_LOCK
#else /* CONTIKIMAC_CONF_WITH_SECURE_PHASE_LOCK */
#define CONTIKIMAC_WITH_SECURE_PHASE_LOCK 1
#endif /* CONTIKIMAC_CONF_WITH_SECURE_PHASE_LOCK */
#endif /* !CONTIKIMAC_FRAMER_POTR_ENABLED */

#if CONTIKIMAC_WITH_SECURE_PHASE_LOCK
#define CONTIKIMAC_WITH_ORIGINAL_PHASE_LOCK 0
#else /* CONTIKIMAC_WITH_SECURE_PHASE_LOCK */
#ifdef CONTIKIMAC_CONF_WITH_ORIGINAL_PHASE_LOCK
#define CONTIKIMAC_WITH_ORIGINAL_PHASE_LOCK CONTIKIMAC_CONF_WITH_ORIGINAL_PHASE_LOCK
#else /* CONTIKIMAC_CONF_WITH_ORIGINAL_PHASE_LOCK */
#define CONTIKIMAC_WITH_ORIGINAL_PHASE_LOCK 1
#endif /* CONTIKIMAC_CONF_WITH_ORIGINAL_PHASE_LOCK */
#endif /* CONTIKIMAC_WITH_SECURE_PHASE_LOCK */

#define CONTIKIMAC_WITH_PHASE_LOCK (CONTIKIMAC_WITH_SECURE_PHASE_LOCK || CONTIKIMAC_WITH_ORIGINAL_PHASE_LOCK)
#define CONTIKIMAC_Q_LEN (CONTIKIMAC_WITH_SECURE_PHASE_LOCK ? 8 : 0)

#if CONTIKIMAC_FRAMER_POTR_ENABLED
#if CONTIKIMAC_WITH_SECURE_PHASE_LOCK
#define CONTIKIMAC_DEFAULT_ACKNOWLEDGEMENT_LEN (2 + AKES_MAC_UNICAST_MIC_LEN)
#define CONTIKIMAC_HELLOACK_ACKNOWLEDGEMENT_LEN (1)
#else /* CONTIKIMAC_WITH_SECURE_PHASE_LOCK */
#define CONTIKIMAC_DEFAULT_ACKNOWLEDGEMENT_LEN (1)
#define CONTIKIMAC_HELLOACK_ACKNOWLEDGEMENT_LEN (1)
#endif /* CONTIKIMAC_WITH_SECURE_PHASE_LOCK */
#else /* CONTIKIMAC_FRAMER_POTR_ENABLED */
#if AKES_MAC_ENABLED
#define CONTIKIMAC_DEFAULT_ACKNOWLEDGEMENT_LEN (CONTIKIMAC_FRAMER_AUTHENTICATED_ACKNOWLEDGEMENT_LEN)
#define CONTIKIMAC_HELLOACK_ACKNOWLEDGEMENT_LEN (CONTIKIMAC_FRAMER_ORIGINAL_UNAUTHENTICATED_ACKNOWLEDGEMENT_LEN)
#else /* AKES_MAC_ENABLED */
#define CONTIKIMAC_DEFAULT_ACKNOWLEDGEMENT_LEN (CONTIKIMAC_FRAMER_ORIGINAL_UNAUTHENTICATED_ACKNOWLEDGEMENT_LEN)
#define CONTIKIMAC_HELLOACK_ACKNOWLEDGEMENT_LEN (CONTIKIMAC_FRAMER_ORIGINAL_UNAUTHENTICATED_ACKNOWLEDGEMENT_LEN)
#endif /* AKES_MAC_ENABLED */
#endif /* CONTIKIMAC_FRAMER_POTR_ENABLED */

#define CONTIKIMAC_UPDATE_ACKNOWLEDGEMENT_LEN (CONTIKIMAC_DEFAULT_ACKNOWLEDGEMENT_LEN \
    + (ANTI_REPLAY_WITH_SUPPRESSION ? 4 : 0))
#if ANTI_REPLAY_WITH_SUPPRESSION && !CONTIKIMAC_WITH_SECURE_PHASE_LOCK
#error forbidden config
#endif /* ANTI_REPLAY_WITH_SUPPRESSION && !CONTIKIMAC_WITH_SECURE_PHASE_LOCK */

/* TODO handle these CC2538-specific adjustments in rtimer.c */
#define CONTIKIMAC_LPM_SWITCHING (1)
#define CONTIKIMAC_LPM_DEEP_SWITCHING (1)
#ifdef LPM_CONF_ENABLE
#if LPM_CONF_ENABLE
#if (LPM_CONF_MAX_PM == LPM_PM1)
#undef CONTIKIMAC_LPM_SWITCHING
#define CONTIKIMAC_LPM_SWITCHING (9)
#undef CONTIKIMAC_LPM_DEEP_SWITCHING
#define CONTIKIMAC_LPM_DEEP_SWITCHING (9)
#elif (LPM_CONF_MAX_PM == LPM_PM2)
#undef CONTIKIMAC_LPM_SWITCHING
#define CONTIKIMAC_LPM_SWITCHING (9)
#undef CONTIKIMAC_LPM_DEEP_SWITCHING
#define CONTIKIMAC_LPM_DEEP_SWITCHING (13)
#else
#warning unsupported power mode
#endif
#endif /* LPM_CONF_ENABLE */
#endif /* LPM_CONF_ENABLE */

#ifdef CONTIKIMAC_CONF_MAX_CCAS
#define CONTIKIMAC_MAX_CCAS CONTIKIMAC_CONF_MAX_CCAS
#else /* CONTIKIMAC_CONF_MAX_CCAS */
#define CONTIKIMAC_MAX_CCAS 2
#endif /* CONTIKIMAC_CONF_MAX_CCAS */

#ifdef CONTIKIMAC_CONF_ACKNOWLEDGEMENT_WINDOW_MAX
#define CONTIKIMAC_ACKNOWLEDGEMENT_WINDOW_MAX CONTIKIMAC_CONF_ACKNOWLEDGEMENT_WINDOW_MAX
#else /* CONTIKIMAC_CONF_ACKNOWLEDGEMENT_WINDOW_MAX */
#define CONTIKIMAC_ACKNOWLEDGEMENT_WINDOW_MAX US_TO_RTIMERTICKS(427)
#endif /* CONTIKIMAC_CONF_ACKNOWLEDGEMENT_WINDOW_MAX */

#define CONTIKIMAC_MAX_ACKNOWLEDGEMENT_LEN \
    MAX(MAX(CONTIKIMAC_DEFAULT_ACKNOWLEDGEMENT_LEN, \
            CONTIKIMAC_HELLOACK_ACKNOWLEDGEMENT_LEN), \
        CONTIKIMAC_UPDATE_ACKNOWLEDGEMENT_LEN)
#define CONTIKIMAC_INTER_FRAME_PERIOD (US_TO_RTIMERTICKS(1068))
#define CONTIKIMAC_INTER_CCA_PERIOD \
    ((CONTIKIMAC_INTER_FRAME_PERIOD - RADIO_RECEIVE_CALIBRATION_TIME + 4) \
    / (CONTIKIMAC_MAX_CCAS - 1))
#define CONTIKIMAC_INTRA_COLLISION_AVOIDANCE_DURATION (CONTIKIMAC_WITH_INTRA_COLLISION_AVOIDANCE \
    ? ((2 * (RADIO_RECEIVE_CALIBRATION_TIME + RADIO_CCA_TIME)) + CONTIKIMAC_INTER_CCA_PERIOD) \
    : (0))
#define CONTIKIMAC_STROBE_GUARD_TIME (CONTIKIMAC_LPM_SWITCHING \
    + CONTIKIMAC_INTRA_COLLISION_AVOIDANCE_DURATION \
    + RADIO_TRANSMIT_CALIBRATION_TIME)
#define CONTIKIMAC_ACKNOWLEDGEMENT_WINDOW_MIN (US_TO_RTIMERTICKS(336))
#define CONTIKIMAC_ACKNOWLEDGEMENT_WINDOW (CONTIKIMAC_ACKNOWLEDGEMENT_WINDOW_MAX \
    - CONTIKIMAC_ACKNOWLEDGEMENT_WINDOW_MIN \
    + 1)

struct contikimac_phase {
#if CONTIKIMAC_WITH_SECURE_PHASE_LOCK
  rtimer_clock_t t;
#endif /* CONTIKIMAC_WITH_SECURE_PHASE_LOCK */
#if CONTIKIMAC_FRAMER_POTR_ILOS_ENABLED
  wake_up_counter_t his_wake_up_counter_at_t;
#endif /* CONTIKIMAC_FRAMER_POTR_ILOS_ENABLED */
#if CONTIKIMAC_WITH_ORIGINAL_PHASE_LOCK
  uint8_t fail_streak;
  rtimer_clock_t t0;
  rtimer_clock_t t1;
#endif /* CONTIKIMAC_WITH_ORIGINAL_PHASE_LOCK */
};

typedef union {
  struct {
    int cca_count;
    rtimer_clock_t silence_timeout;
    int set_silence_timeout;
    int got_shr;
    int waiting_for_shr;
    int rejected_frame;
    struct packetbuf local_packetbuf;
    struct packetbuf *actual_packetbuf;
    int shall_send_acknowledgement;
    int got_frame;
    uint8_t acknowledgement[1 /* Frame Length */ + CONTIKIMAC_MAX_ACKNOWLEDGEMENT_LEN];
#if CONTIKIMAC_WITH_SECURE_PHASE_LOCK
    int read_and_parsed;
    int is_helloack;
    int is_ack;
#endif /* CONTIKIMAC_WITH_SECURE_PHASE_LOCK */
  } duty_cycle;

  struct {
    int cca_count;
    int is_waiting_for_acknowledgement_shr;
    int got_acknowledgement_shr;
    uint8_t prepared_frame[1 /* Frame Length */ + RADIO_MAX_FRAME_LEN];
    int is_broadcast;
    int result;
    rtimer_clock_t next_transmission;
    rtimer_clock_t timeout;
    struct buffered_frame *bf;
    int sent_once_more;
    uint8_t acknowledgement[CONTIKIMAC_MAX_ACKNOWLEDGEMENT_LEN];
    uint8_t acknowledgement_len;
#if AKES_MAC_ENABLED
    int is_hello;
    int is_helloack;
    int is_ack;
    uint8_t nonce[CCM_STAR_NONCE_LENGTH];
    uint8_t acknowledgement_key[AES_128_KEY_LENGTH];
#if !CONTIKIMAC_FRAMER_POTR_ENABLED
    frame802154_frame_counter_t his_unicast_counter;
#endif /* !CONTIKIMAC_FRAMER_POTR_ENABLED */
#endif /* AKES_MAC_ENABLED */
#if CONTIKIMAC_FRAMER_POTR_ILOS_ENABLED
    wake_up_counter_t receivers_wake_up_counter;
#endif /* CONTIKIMAC_FRAMER_POTR_ILOS_ENABLED */
#if CONTIKIMAC_WITH_PHASE_LOCK
    rtimer_clock_t t1[2];
#endif /* CONTIKIMAC_WITH_PHASE_LOCK */
#if CONTIKIMAC_WITH_ORIGINAL_PHASE_LOCK
    rtimer_clock_t t0[2];
#endif /* CONTIKIMAC_WITH_ORIGINAL_PHASE_LOCK */
    uint8_t strobes;
#if CONTIKIMAC_WITH_SECURE_PHASE_LOCK
    uint8_t shall_encrypt;
    uint8_t a_len;
    uint8_t m_len;
    uint8_t mic_len;
    uint8_t totlen;
    uint8_t unsecured_frame[RADIO_MAX_FRAME_LEN];
    uint8_t strobe_index_offset;
    uint8_t phase_offset;
    uint8_t key[AES_128_KEY_LENGTH];
#else /* CONTIKIMAC_WITH_SECURE_PHASE_LOCK */
    uint8_t seqno;
#endif /* CONTIKIMAC_WITH_SECURE_PHASE_LOCK */
  } strobe;
} contikimac_state_t;

#if CONTIKIMAC_WITH_ORIGINAL_PHASE_LOCK
rtimer_clock_t contikimac_get_last_but_one_t0(void);
#endif /* CONTIKIMAC_WITH_ORIGINAL_PHASE_LOCK */
#if CONTIKIMAC_WITH_PHASE_LOCK
rtimer_clock_t contikimac_get_last_but_one_t1(void);
#endif /* CONTIKIMAC_WITH_PHASE_LOCK */
#if CONTIKIMAC_WITH_SECURE_PHASE_LOCK
rtimer_clock_t contikimac_get_sfd_timestamp(void);
rtimer_clock_t contikimac_get_phase(void);
uint8_t contikimac_get_last_delta(void);
uint8_t contikimac_get_last_strobe_index(void);
int potr_has_strobe_index(enum potr_frame_type type);
rtimer_clock_t contikimac_get_last_wake_up_time(void);
#if CONTIKIMAC_FRAMER_POTR_ILOS_ENABLED
rtimer_clock_t contikimac_get_next_strobe_start(void);
wake_up_counter_t contikimac_get_wake_up_counter(rtimer_clock_t t);
wake_up_counter_t contikimac_predict_wake_up_counter(void);
wake_up_counter_t contikimac_restore_wake_up_counter(void);
#endif /* CONTIKIMAC_FRAMER_POTR_ILOS_ENABLED */
#endif /* CONTIKIMAC_WITH_SECURE_PHASE_LOCK */

extern const struct mac_driver contikimac_driver;
extern contikimac_state_t contikimac_state;
extern const struct contikimac_framer CONTIKIMAC_FRAMER;

#endif /* CONTIKIMAC_H_ */
