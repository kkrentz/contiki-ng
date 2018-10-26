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

#include "net/mac/contikimac/contikimac.h"
#include "net/mac/contikimac/contikimac-ccm-inputs.h"
#include "net/mac/contikimac/contikimac-nbr.h"
#include "net/mac/contikimac/contikimac-synchronizer.h"
#include "net/mac/mac.h"
#include "net/netstack.h"
#include "net/queuebuf.h"
#include "lib/memb.h"
#include "lib/list.h"
#include "net/mac/contikimac/contikimac-framer-original.h"
#include "net/mac/framer/crc16-framer.h"
#include "services/akes/akes.h"
#include "services/akes/akes-nbr.h"
#include "net/mac/mac-sequence.h"
#include "net/nbr-table.h"
#include "dev/crypto.h"
#include "lib/aes-128.h"
#include "lib/random.h"
#include "sys/energest.h"

#ifdef CONTIKIMAC_CONF_CCA_THRESHOLD_TRANSMISSION_DETECTION
#define CCA_THRESHOLD_TRANSMISSION_DETECTION CONTIKIMAC_CONF_CCA_THRESHOLD_TRANSMISSION_DETECTION
#else /* CONTIKIMAC_CONF_CCA_THRESHOLD_TRANSMISSION_DETECTION */
#define CCA_THRESHOLD_TRANSMISSION_DETECTION (-80)
#endif /* CONTIKIMAC_CONF_CCA_THRESHOLD_TRANSMISSION_DETECTION */

#ifdef CONTIKIMAC_CONF_CCA_THRESHOLD_SILENCE_DETECTION
#define CCA_THRESHOLD_SILENCE_DETECTION CONTIKIMAC_CONF_CCA_THRESHOLD_SILENCE_DETECTION
#else /* CONTIKIMAC_CONF_CCA_THRESHOLD_SILENCE_DETECTION */
#define CCA_THRESHOLD_SILENCE_DETECTION (CCA_THRESHOLD_TRANSMISSION_DETECTION)
#endif /* CONTIKIMAC_CONF_CCA_THRESHOLD_SILENCE_DETECTION */

#ifdef CONTIKIMAC_CONF_CCA_THRESHOLD_COLLISION_AVOIDANCE
#define CCA_THRESHOLD_COLLISION_AVOIDANCE CONTIKIMAC_CONF_CCA_THRESHOLD_COLLISION_AVOIDANCE
#else /* CONTIKIMAC_CONF_CCA_THRESHOLD_COLLISION_AVOIDANCE */
#define CCA_THRESHOLD_COLLISION_AVOIDANCE (-70)
#endif /* CONTIKIMAC_CONF_CCA_THRESHOLD_COLLISION_AVOIDANCE */

#ifdef CONTIKIMAC_CONF_MAX_RETRANSMISSIONS
#define MAX_RETRANSMISSIONS CONTIKIMAC_CONF_MAX_RETRANSMISSIONS
#else /* CONTIKIMAC_CONF_MAX_RETRANSMISSIONS */
#define MAX_RETRANSMISSIONS 5
#endif /* CONTIKIMAC_CONF_MAX_RETRANSMISSIONS */

#ifdef CONTIKIMAC_CONF_WITH_DOZING
#define WITH_DOZING CONTIKIMAC_CONF_WITH_DOZING
#else /* CONTIKIMAC_CONF_WITH_DOZING */
#define WITH_DOZING 1
#endif /* CONTIKIMAC_CONF_WITH_DOZING */

#define MIN_BACK_OFF_EXPONENT 3
#define MAX_BACK_OFF_EXPONENT 5
#define MAX_NOISE RADIO_TIME_TO_TRANSMIT( \
    (RADIO_PHY_HEADER_LEN + RADIO_MAX_FRAME_LEN) * RADIO_SYMBOLS_PER_BYTE)
#define CCA_SLEEP_DURATION (RADIO_RECEIVE_CALIBRATION_TIME \
    + RADIO_CCA_TIME \
    - 3)
#define SILENCE_CHECK_PERIOD (US_TO_RTIMERTICKS(250))
#define DOZING_PERIOD (CONTIKIMAC_INTER_FRAME_PERIOD \
    - RADIO_RECEIVE_CALIBRATION_TIME \
    - RADIO_CCA_TIME)

/* Log configuration */
#include "sys/log.h"
#define LOG_MODULE "ContikiMAC"
#define LOG_LEVEL LOG_LEVEL_MAC

enum cca_reason {
  TRANSMISSION_DETECTION = 0,
  SILENCE_DETECTION,
  COLLISION_AVOIDANCE
};

struct buffered_frame {
  struct buffered_frame *next;
  struct queuebuf *qb;
  mac_callback_t sent;
  int transmissions;
  rtimer_clock_t next_attempt;
  void *ptr;
};

static void schedule_duty_cycle(rtimer_clock_t time);
static int schedule_duty_cycle_precise(rtimer_clock_t time);
static void duty_cycle_wrapper(struct rtimer *t, void *ptr);
static char duty_cycle(void);
static void on_shr(void);
static void on_fifop(void);
static void on_final_fifop(void);
#if CONTIKIMAC_WITH_SECURE_PHASE_LOCK
static int received_authentic_unicast(void);
static int is_valid_ack(struct akes_nbr_entry *entry);
#endif /* CONTIKIMAC_WITH_SECURE_PHASE_LOCK */
static void on_txdone(void);
static struct buffered_frame *select_next_frame_to_transmit(void);
static void schedule_strobe(rtimer_clock_t time);
static int schedule_strobe_precise(rtimer_clock_t time);
static void strobe_wrapper(struct rtimer *rt, void *ptr);
static char strobe(void);
static int should_strobe_again(void);
static int transmit(void);
static void on_strobed(void);
static void try_skip_to_send(void);
static void queue_frame(mac_callback_t sent, void *ptr);

contikimac_state_t contikimac_state;
static const int16_t cca_thresholds[] =
    { CCA_THRESHOLD_TRANSMISSION_DETECTION ,
      CCA_THRESHOLD_SILENCE_DETECTION ,
      CCA_THRESHOLD_COLLISION_AVOIDANCE };
static struct rtimer timer;
static rtimer_clock_t duty_cycle_next;
static struct pt pt;
static volatile int is_duty_cycling;
static volatile int is_strobing;
static volatile int can_skip;
static volatile int skipped;
PROCESS(post_processing, "post processing");
MEMB(buffered_frames_memb, struct buffered_frame, QUEUEBUF_NUM);
LIST(buffered_frames_list);
#if CONTIKIMAC_WITH_SECURE_PHASE_LOCK
static volatile rtimer_clock_t sfd_timestamp;
#if CONTIKIMAC_FRAMER_POTR_ILOS_ENABLED
static wake_up_counter_t my_wake_up_counter;
static rtimer_clock_t my_wake_up_counter_last_increment;
#endif /* CONTIKIMAC_FRAMER_POTR_ILOS_ENABLED */
#endif /* CONTIKIMAC_WITH_SECURE_PHASE_LOCK */
#if !AKES_MAC_ENABLED
static uint8_t mac_dsn;
#endif /* !AKES_MAC_ENABLED */

/*---------------------------------------------------------------------------*/
static int
channel_clear(enum cca_reason reason)
{
  return radio_get_rssi() < cca_thresholds[reason];
}
/*---------------------------------------------------------------------------*/
static void
init(void)
{
  NETSTACK_RADIO.enter_async_mode();
  LOG_INFO("t_i = %lu\n", CONTIKIMAC_INTER_FRAME_PERIOD);
  LOG_INFO("t_c = %lu\n", CONTIKIMAC_INTER_CCA_PERIOD);
  LOG_INFO("t_w = %i\n", WAKE_UP_COUNTER_INTERVAL);
  memb_init(&buffered_frames_memb);
  list_init(buffered_frames_list);
#if !AKES_MAC_ENABLED
  mac_dsn = random_rand();
#endif /* !AKES_MAC_ENABLED */
  CONTIKIMAC_FRAMER.init();
  CONTIKIMAC_SYNCHRONIZER.init();
  NETSTACK_RADIO.async_set_txdone_callback(on_txdone);
  NETSTACK_RADIO.async_set_shr_callback(on_shr);
  process_start(&post_processing, NULL);
  PT_INIT(&pt);
  duty_cycle_next = RTIMER_NOW() + WAKE_UP_COUNTER_INTERVAL;
  schedule_duty_cycle(duty_cycle_next - CONTIKIMAC_LPM_DEEP_SWITCHING);
}
/*---------------------------------------------------------------------------*/
static void
schedule_duty_cycle(rtimer_clock_t time)
{
  if(rtimer_set(&timer, time, 1, duty_cycle_wrapper, NULL) != RTIMER_OK) {
    LOG_ERR("rtimer_set failed\n");
  }
}
/*---------------------------------------------------------------------------*/
static int
schedule_duty_cycle_precise(rtimer_clock_t time)
{
  timer.time = time;
  timer.func = duty_cycle_wrapper;
  timer.ptr = NULL;
  return rtimer_set_precise(&timer);
}
/*---------------------------------------------------------------------------*/
static void
duty_cycle_wrapper(struct rtimer *rt, void *ptr)
{
  duty_cycle();
}
/*---------------------------------------------------------------------------*/
static char
duty_cycle(void)
{
  PT_BEGIN(&pt);

  can_skip = 0;
  is_duty_cycling = 1;
#ifdef LPM_CONF_ENABLE
  lpm_set_max_pm(LPM_PM1);
#endif /* LPM_CONF_ENABLE */
  if(skipped) {
    skipped = 0;
  } else {
#if CONTIKIMAC_FRAMER_POTR_ILOS_ENABLED
    my_wake_up_counter = contikimac_get_wake_up_counter(contikimac_get_last_wake_up_time());
    my_wake_up_counter_last_increment = contikimac_get_last_wake_up_time();
#endif /* CONTIKIMAC_FRAMER_POTR_ILOS_ENABLED */

    NETSTACK_RADIO.async_set_fifop_callback(on_fifop, 1 /* Frame Length */ + CONTIKIMAC_FRAMER.get_min_bytes_for_filtering());
    NETSTACK_RADIO.set_value(RADIO_PARAM_SHR_SEARCH, RADIO_SHR_SEARCH_DIS);

    /* if we come from PM0, we will be too early */
    while(!rtimer_has_timed_out(duty_cycle_next));

    /* CCAs */
    while(1) {
      NETSTACK_RADIO.async_on();
      schedule_duty_cycle(RTIMER_NOW() + CCA_SLEEP_DURATION);
      PT_YIELD(&pt);
      if(channel_clear(TRANSMISSION_DETECTION)) {
        NETSTACK_RADIO.async_off();
        if(++contikimac_state.duty_cycle.cca_count != CONTIKIMAC_MAX_CCAS) {
          schedule_duty_cycle(RTIMER_NOW() + CONTIKIMAC_INTER_CCA_PERIOD - CONTIKIMAC_LPM_SWITCHING);
          PT_YIELD(&pt);
          /* if we come from PM0, we will be too early */
          while(!rtimer_has_timed_out(timer.time));
          continue;
        }
      } else {
        contikimac_state.duty_cycle.silence_timeout = RTIMER_NOW()
            + MAX_NOISE
            + RADIO_CCA_TIME;
        contikimac_state.duty_cycle.set_silence_timeout = 1;
      }
      break;
    }

    /* fast-sleep optimization */
    if(contikimac_state.duty_cycle.set_silence_timeout) {
      while(1) {

        /* look for silence period */
#if WITH_DOZING
        NETSTACK_RADIO.async_off();
        schedule_duty_cycle(RTIMER_NOW() + DOZING_PERIOD - CONTIKIMAC_LPM_SWITCHING - 2);
        PT_YIELD(&pt);
        NETSTACK_RADIO.async_on();
        schedule_duty_cycle(RTIMER_NOW() + CCA_SLEEP_DURATION);
        PT_YIELD(&pt);
#else /* WITH_DOZING */
        schedule_duty_cycle(RTIMER_NOW() + SILENCE_CHECK_PERIOD);
        PT_YIELD(&pt);
#endif /* WITH_DOZING */
        if(channel_clear(SILENCE_DETECTION)) {
          NETSTACK_RADIO.set_value(RADIO_PARAM_SHR_SEARCH, RADIO_SHR_SEARCH_EN);

          /* wait for SHR */
          contikimac_state.duty_cycle.waiting_for_shr = 1;
          schedule_duty_cycle(RTIMER_NOW()
              + CONTIKIMAC_INTER_FRAME_PERIOD
              + RADIO_SHR_TIME
              + 3 /* some tolerance */);
          PT_YIELD(&pt); /* wait for timeout or on_fifop, whatever comes first */
          if(contikimac_state.duty_cycle.rejected_frame) {
            rtimer_cancel();
          }
          contikimac_state.duty_cycle.waiting_for_shr = 0;
          if(!contikimac_state.duty_cycle.got_shr) {
            NETSTACK_RADIO.async_off();
            LOG_WARN("no SHR detected\n");
          } else {
            PT_YIELD(&pt); /* wait for timeout or on_fifop, whatever comes last */
            if(!contikimac_state.duty_cycle.rejected_frame) {
              PT_YIELD(&pt); /* wait for on_final_fifop or on_txdone */
            }
          }
          break;
        } else if(rtimer_has_timed_out(contikimac_state.duty_cycle.silence_timeout)) {
          NETSTACK_RADIO.async_off();
          LOG_WARN("noise too long\n");
          break;
        }
      }
    }
  }

  NETSTACK_RADIO.async_set_fifop_callback(NULL, 0);
  NETSTACK_RADIO.set_value(RADIO_PARAM_SHR_SEARCH, RADIO_SHR_SEARCH_EN);
  is_duty_cycling = 0;
  process_poll(&post_processing);

  PT_END(&pt);
}
/*---------------------------------------------------------------------------*/
/**
 * Here, we assume that rtimer and radio interrupts have equal priorities,
 * such that they do not preempt each other.
 */
static void
on_shr(void)
{
  if(is_duty_cycling && contikimac_state.duty_cycle.waiting_for_shr) {
#if CONTIKIMAC_WITH_SECURE_PHASE_LOCK
    sfd_timestamp = RTIMER_NOW();
#endif /* CONTIKIMAC_WITH_SECURE_PHASE_LOCK */
    contikimac_state.duty_cycle.got_shr = 1;
#if CRYPTO_CONF_INIT
    crypto_enable();
#endif /* CRYPTO_CONF_INIT */
  } else if(is_strobing) {
#if CONTIKIMAC_WITH_SECURE_PHASE_LOCK
    sfd_timestamp = RTIMER_NOW();
#endif /* CONTIKIMAC_WITH_SECURE_PHASE_LOCK */
    if(contikimac_state.strobe.is_waiting_for_acknowledgement_shr) {
      contikimac_state.strobe.got_acknowledgement_shr = 1;
    } else {
#if CONTIKIMAC_WITH_SECURE_PHASE_LOCK
      contikimac_framer_potr_update_contents();
#endif /* CONTIKIMAC_WITH_SECURE_PHASE_LOCK */
    }
  }
}
/*---------------------------------------------------------------------------*/
static void
enable_local_packetbuf(void)
{
  contikimac_state.duty_cycle.actual_packetbuf = packetbuf;
  packetbuf = &contikimac_state.duty_cycle.local_packetbuf;
}
/*---------------------------------------------------------------------------*/
static void
disable_local_packetbuf(void)
{
  packetbuf = contikimac_state.duty_cycle.actual_packetbuf;
}
/*---------------------------------------------------------------------------*/
#if CONTIKIMAC_FRAMER_POTR_ENABLED
static int
is_anything_locked(void)
{
  return aes_128_locked || akes_nbr_locked || nbr_table_locked;
}
#endif /* !CONTIKIMAC_FRAMER_POTR_ENABLED */
/*---------------------------------------------------------------------------*/
static void
on_fifop(void)
{
#if CONTIKIMAC_WITH_SECURE_PHASE_LOCK
  uint8_t *hdrptr;
#endif /* CONTIKIMAC_WITH_SECURE_PHASE_LOCK */

  if(!contikimac_state.duty_cycle.got_shr) {
    return;
  }

  /* avoid that on_fifop is called twice if FIFOP_THRESHOLD is very low */
  NETSTACK_RADIO.async_set_fifop_callback(NULL, RADIO_MAX_FRAME_LEN);
  enable_local_packetbuf();
  if(0
#if CONTIKIMAC_FRAMER_POTR_ENABLED
      || is_anything_locked()
#endif /* !CONTIKIMAC_FRAMER_POTR_ENABLED */
      || !NETSTACK_RADIO.async_read_phy_header_to_packetbuf()
      || (CONTIKIMAC_FRAMER.filter(contikimac_state.duty_cycle.acknowledgement) == FRAMER_FAILED)) {
    NETSTACK_RADIO.async_off();
    LOG_ERR("rejected frame of length %i\n", packetbuf_datalen());
    contikimac_state.duty_cycle.rejected_frame = 1;
  } else {
    packetbuf_set_attr(PACKETBUF_ATTR_RSSI, radio_get_rssi());
    contikimac_state.duty_cycle.shall_send_acknowledgement = !packetbuf_holds_broadcast();
#if CONTIKIMAC_WITH_SECURE_PHASE_LOCK
    hdrptr = packetbuf_hdrptr();
    contikimac_state.duty_cycle.is_helloack = hdrptr[0] == CONTIKIMAC_FRAMER_POTR_FRAME_TYPE_HELLOACK;
    contikimac_state.duty_cycle.is_ack = hdrptr[0] == CONTIKIMAC_FRAMER_POTR_FRAME_TYPE_ACK;
#endif /* CONTIKIMAC_WITH_SECURE_PHASE_LOCK */

    if(contikimac_state.duty_cycle.shall_send_acknowledgement) {
      NETSTACK_RADIO.async_prepare(contikimac_state.duty_cycle.acknowledgement);
    }
    NETSTACK_RADIO.async_set_fifop_callback(on_final_fifop,
        NETSTACK_RADIO.async_remaining_payload_bytes());
  }
  disable_local_packetbuf();
  duty_cycle();
}
/*---------------------------------------------------------------------------*/
static void
on_final_fifop(void)
{
  /* avoid that on_final_fifop is called twice */
  NETSTACK_RADIO.async_set_fifop_callback(NULL, 0);

  contikimac_state.duty_cycle.got_frame = 1;
  if(!contikimac_state.duty_cycle.shall_send_acknowledgement) {
    NETSTACK_RADIO.async_off();
    duty_cycle();
    return;
  }

  NETSTACK_RADIO.async_transmit(0);
#if CONTIKIMAC_WITH_SECURE_PHASE_LOCK
  if(!received_authentic_unicast()) {
    NETSTACK_RADIO.async_off();
    contikimac_state.duty_cycle.got_frame = 0;
    LOG_ERR("aborted transmission of acknowledgement frame\n");
    duty_cycle();
  }
#endif /* CONTIKIMAC_WITH_SECURE_PHASE_LOCK */
}
/*---------------------------------------------------------------------------*/
#if CONTIKIMAC_WITH_SECURE_PHASE_LOCK
static int
received_authentic_unicast(void)
{
  struct akes_nbr_entry *entry;

  if(contikimac_state.duty_cycle.is_helloack) {
    /* HELLOACKs are parsed and verified later */
    return 1;
  }

  enable_local_packetbuf();

  contikimac_state.duty_cycle.read_and_parsed = !is_anything_locked()
      && NETSTACK_RADIO.async_read_payload_to_packetbuf(NETSTACK_RADIO.async_remaining_payload_bytes())
      && (NETSTACK_FRAMER.parse() != FRAMER_FAILED)
      && ((entry = akes_nbr_get_sender_entry()))
      && ((!contikimac_state.duty_cycle.is_ack
          && entry->permanent
          && !AKES_MAC_STRATEGY.verify(entry->permanent))
      || (contikimac_state.duty_cycle.is_ack
          && is_valid_ack(entry)));

  disable_local_packetbuf();
  return contikimac_state.duty_cycle.read_and_parsed;
}
/*---------------------------------------------------------------------------*/
static int
is_valid_ack(struct akes_nbr_entry *entry)
{
  uint8_t *dataptr;
  contikimac_nbr_tentative_t *contikimac_nbr_tentative;

  dataptr = packetbuf_dataptr();
  dataptr += AKES_ACK_PIGGYBACK_OFFSET
      + (ANTI_REPLAY_WITH_SUPPRESSION ? 4 : 0);
  packetbuf_set_attr(PACKETBUF_ATTR_UNENCRYPTED_BYTES,
      packetbuf_datalen() - AES_128_KEY_LENGTH - AKES_MAC_UNICAST_MIC_LEN);
  contikimac_nbr_tentative =
      contikimac_nbr_get_tentative(entry->tentative->meta);
  if((dataptr[CONTIKIMAC_Q_LEN] != contikimac_nbr_tentative->strobe_index)
      || memcmp(dataptr, contikimac_nbr_tentative->q, CONTIKIMAC_Q_LEN)
      || akes_mac_verify(entry->tentative->tentative_pairwise_key)) {
    LOG_ERR("invalid ACK\n");
    akes_nbr_delete(entry, AKES_NBR_TENTATIVE);
    return 0;
  } else {
    return 1;
  }
}
#endif /* CONTIKIMAC_WITH_SECURE_PHASE_LOCK */
/*---------------------------------------------------------------------------*/
static void
on_txdone(void)
{
  if(is_duty_cycling) {
    duty_cycle();
  } else if(is_strobing) {
#if CONTIKIMAC_WITH_PHASE_LOCK
    contikimac_state.strobe.t1[0] = contikimac_state.strobe.t1[1];
    contikimac_state.strobe.t1[1] = RTIMER_NOW();
#endif /* CONTIKIMAC_WITH_PHASE_LOCK */
    strobe();
  }
}
/*---------------------------------------------------------------------------*/
rtimer_clock_t
contikimac_get_last_wake_up_time(void)
{
  return duty_cycle_next + RADIO_RECEIVE_CALIBRATION_TIME;
}
/*---------------------------------------------------------------------------*/
#if CONTIKIMAC_WITH_ORIGINAL_PHASE_LOCK
rtimer_clock_t
contikimac_get_last_but_one_t0(void)
{
  return contikimac_state.strobe.t0[0];
}
#endif /* CONTIKIMAC_WITH_ORIGINAL_PHASE_LOCK */
/*---------------------------------------------------------------------------*/
#if CONTIKIMAC_WITH_PHASE_LOCK
rtimer_clock_t
contikimac_get_last_but_one_t1(void)
{
  return contikimac_state.strobe.t1[0];
}
#endif /* CONTIKIMAC_WITH_PHASE_LOCK */
/*---------------------------------------------------------------------------*/
#if CONTIKIMAC_WITH_SECURE_PHASE_LOCK
rtimer_clock_t
contikimac_get_sfd_timestamp(void)
{
  return sfd_timestamp;
}
/*---------------------------------------------------------------------------*/
rtimer_clock_t
contikimac_get_phase(void)
{
  rtimer_clock_t result;

  result = RTIMER_CLOCK_DIFF(sfd_timestamp, contikimac_get_last_wake_up_time());
  while(result >= WAKE_UP_COUNTER_INTERVAL) {
    result -= WAKE_UP_COUNTER_INTERVAL;
  }
  return WAKE_UP_COUNTER_INTERVAL - result;
}
/*---------------------------------------------------------------------------*/
uint8_t
contikimac_get_last_delta(void)
{
  return sfd_timestamp
      - contikimac_get_last_wake_up_time()
      - CONTIKIMAC_INTER_FRAME_PERIOD
      - RADIO_SHR_TIME;
}
/*---------------------------------------------------------------------------*/
uint8_t
contikimac_get_last_strobe_index(void)
{
  return contikimac_state.strobe.strobes;
}
/*---------------------------------------------------------------------------*/
#if CONTIKIMAC_FRAMER_POTR_ILOS_ENABLED
rtimer_clock_t
contikimac_get_next_strobe_start(void)
{
  return contikimac_state.strobe.next_transmission;
}
#endif /* CONTIKIMAC_FRAMER_POTR_ILOS_ENABLED */
#endif /* CONTIKIMAC_WITH_SECURE_PHASE_LOCK */
/*---------------------------------------------------------------------------*/
PROCESS_THREAD(post_processing, ev, data)
{
  int just_received_broadcast;
  struct buffered_frame *next;

  PROCESS_BEGIN();

  while(1) {
    PROCESS_YIELD_UNTIL(ev == PROCESS_EVENT_POLL);

    just_received_broadcast = 0;

    /* read received frame */
    if(contikimac_state.duty_cycle.got_frame) {
      enable_local_packetbuf();
#if CONTIKIMAC_WITH_SECURE_PHASE_LOCK
      if(!contikimac_state.duty_cycle.read_and_parsed
#else /* CONTIKIMAC_WITH_SECURE_PHASE_LOCK */
      if(1
#endif /* CONTIKIMAC_WITH_SECURE_PHASE_LOCK */
          && ((!NETSTACK_RADIO.async_read_payload_to_packetbuf(NETSTACK_RADIO.async_remaining_payload_bytes())
              || (NETSTACK_FRAMER.parse() == FRAMER_FAILED)))) {
        LOG_ERR("something went wrong while reading\n");
      } else {
        just_received_broadcast = packetbuf_holds_broadcast();
#if AKES_MAC_ENABLED
        NETSTACK_MAC.input();
#else /* AKES_MAC_ENABLED */
        if(mac_sequence_is_duplicate()) {
          LOG_WARN("received duplicate\n");
        } else {
          mac_sequence_register_seqno();
          NETSTACK_NETWORK.input();
        }
#endif /* AKES_MAC_ENABLED */
      }
      disable_local_packetbuf();
    }

    /* send queued frames */
    if(!just_received_broadcast) {
      while((next = select_next_frame_to_transmit())) {
#if CRYPTO_CONF_INIT
        crypto_enable();
#endif /* CRYPTO_CONF_INIT */
        memset(&contikimac_state.strobe, 0, sizeof(contikimac_state.strobe));
        contikimac_state.strobe.bf = next;
        queuebuf_to_packetbuf(contikimac_state.strobe.bf->qb);
        contikimac_state.strobe.is_broadcast = packetbuf_holds_broadcast();

#if AKES_MAC_ENABLED
        if(akes_mac_is_hello()) {
          contikimac_state.strobe.is_hello = 1;
        } else if(akes_mac_is_helloack()) {
          contikimac_state.strobe.is_helloack = 1;
          contikimac_state.strobe.acknowledgement_len = CONTIKIMAC_HELLOACK_ACKNOWLEDGEMENT_LEN;
        } else if(akes_mac_is_ack()) {
          contikimac_state.strobe.is_ack = 1;
          contikimac_state.strobe.acknowledgement_len = CONTIKIMAC_DEFAULT_ACKNOWLEDGEMENT_LEN;
        } else if(akes_mac_is_update()) {
          contikimac_state.strobe.acknowledgement_len = CONTIKIMAC_UPDATE_ACKNOWLEDGEMENT_LEN;
        } else {
          contikimac_state.strobe.acknowledgement_len = CONTIKIMAC_DEFAULT_ACKNOWLEDGEMENT_LEN;
        }
#else /* AKES_MAC_ENABLED */
        contikimac_state.strobe.acknowledgement_len = CONTIKIMAC_DEFAULT_ACKNOWLEDGEMENT_LEN;
#endif /* AKES_MAC_ENABLED */

        if(!contikimac_state.strobe.is_broadcast
            && !CONTIKIMAC_FRAMER.prepare_acknowledgement_parsing()) {
          LOG_ERR("prepare_acknowledgement_parsing failed\n");
          contikimac_state.strobe.result = MAC_TX_ERR_FATAL;
          on_strobed();
          continue;
        }

#if CONTIKIMAC_FRAMER_POTR_ILOS_ENABLED
        /* schedule strobe */
        contikimac_state.strobe.result = CONTIKIMAC_SYNCHRONIZER.schedule();
        if(contikimac_state.strobe.result != MAC_TX_OK) {
          on_strobed();
          continue;
        }
#endif /* CONTIKIMAC_FRAMER_POTR_ILOS_ENABLED */

        /* create frame */
#if !CONTIKIMAC_FRAMER_POTR_ENABLED
        packetbuf_set_attr(PACKETBUF_ATTR_MAC_ACK, 1);
        packetbuf_set_addr(PACKETBUF_ADDR_SENDER, &linkaddr_node_addr);
#endif /* !CONTIKIMAC_FRAMER_POTR_ENABLED */
        if(NETSTACK_FRAMER.create() == FRAMER_FAILED) {
          contikimac_state.strobe.result = MAC_TX_ERR_FATAL;
          on_strobed();
          continue;
        }

        /* is this a broadcast? */
#if !CONTIKIMAC_WITH_SECURE_PHASE_LOCK
#if CONTIKIMAC_FRAMER_POTR_ENABLED
        contikimac_state.strobe.seqno = packetbuf_attr(PACKETBUF_ATTR_FRAME_COUNTER_BYTES_0_1) & 0xFF;
#else /* CONTIKIMAC_FRAMER_POTR_ENABLED */
        contikimac_state.strobe.seqno = packetbuf_attr(PACKETBUF_ATTR_MAC_SEQNO);
#endif /* CONTIKIMAC_FRAMER_POTR_ENABLED */
#endif /* !CONTIKIMAC_WITH_SECURE_PHASE_LOCK */

        /* move frame to radio */
        contikimac_state.strobe.prepared_frame[0] = packetbuf_totlen();
        memcpy(contikimac_state.strobe.prepared_frame + 1, packetbuf_hdrptr(), packetbuf_totlen());
        NETSTACK_RADIO.async_prepare(contikimac_state.strobe.prepared_frame);

#if !CONTIKIMAC_FRAMER_POTR_ILOS_ENABLED
        /* schedule strobe */
        contikimac_state.strobe.result = CONTIKIMAC_SYNCHRONIZER.schedule();
        if(contikimac_state.strobe.result != MAC_TX_OK) {
          on_strobed();
          continue;
        }
#endif /* !CONTIKIMAC_FRAMER_POTR_ILOS_ENABLED */

#if CONTIKIMAC_FRAMER_POTR_ILOS_ENABLED
        if(schedule_strobe_precise(contikimac_state.strobe.next_transmission - CONTIKIMAC_STROBE_GUARD_TIME) != RTIMER_OK) {
          LOG_ERR("strobe starts too early\n");
          contikimac_state.strobe.result = MAC_TX_ERR_FATAL;
          on_strobed();
          continue;
        }
#else /* CONTIKIMAC_FRAMER_POTR_ILOS_ENABLED */
        while(schedule_strobe_precise(contikimac_state.strobe.next_transmission - CONTIKIMAC_STROBE_GUARD_TIME) != RTIMER_OK) {
          contikimac_state.strobe.next_transmission += WAKE_UP_COUNTER_INTERVAL;
          contikimac_state.strobe.timeout += WAKE_UP_COUNTER_INTERVAL;
        }
#endif /* CONTIKIMAC_FRAMER_POTR_ILOS_ENABLED */

        /* process strobe result */
        PROCESS_YIELD_UNTIL(ev == PROCESS_EVENT_POLL);
        contikimac_state.strobe.bf->transmissions++;
        on_strobed();
      }
    }
#ifdef LPM_CONF_ENABLE
    lpm_set_max_pm(LPM_CONF_MAX_PM);
#endif /* LPM_CONF_ENABLE */

    /* prepare next duty cycle */
#if CRYPTO_CONF_INIT
    crypto_disable();
#endif /* CRYPTO_CONF_INIT */
    memset(&contikimac_state.duty_cycle, 0, sizeof(contikimac_state.duty_cycle));
    duty_cycle_next = wake_up_counter_shift_to_future(duty_cycle_next);

    while(schedule_duty_cycle_precise(duty_cycle_next - CONTIKIMAC_LPM_DEEP_SWITCHING) != RTIMER_OK) {
      duty_cycle_next += WAKE_UP_COUNTER_INTERVAL;
    }
    can_skip = 1;
  }

  PROCESS_END();
}
/*---------------------------------------------------------------------------*/
static struct buffered_frame *
select_next_frame_to_transmit(void)
{
  rtimer_clock_t now;
  struct buffered_frame *next;

  now = RTIMER_NOW();
  next = list_head(buffered_frames_list);
  while(next) {
    if(RTIMER_CLOCK_LT_OR_EQ(next->next_attempt, now)) {
      if(next->transmissions) {
        LOG_INFO("retransmission %i\n", next->transmissions);
      }
      return next;
    }
    next = list_item_next(next);
  }
  return NULL;
}
/*---------------------------------------------------------------------------*/
static void
schedule_strobe(rtimer_clock_t time)
{
  if(rtimer_set(&timer, time, 1, strobe_wrapper, NULL) != RTIMER_OK) {
    LOG_ERR("rtimer_set failed\n");
  }
}
/*---------------------------------------------------------------------------*/
static int
schedule_strobe_precise(rtimer_clock_t time)
{
  timer.time = time;
  timer.func = strobe_wrapper;
  timer.ptr = NULL;
  return rtimer_set_precise(&timer);
}
/*---------------------------------------------------------------------------*/
static void
strobe_wrapper(struct rtimer *rt, void *ptr)
{
  strobe();
}
/*---------------------------------------------------------------------------*/
static char
strobe(void)
{
  PT_BEGIN(&pt);

  is_strobing = 1;

  while(1) {
    if(!contikimac_state.strobe.strobes) {
#if CONTIKIMAC_WITH_INTRA_COLLISION_AVOIDANCE
      /* if we come from PM0, we will be too early */
      while(!rtimer_has_timed_out(contikimac_state.strobe.next_transmission
          - CONTIKIMAC_INTRA_COLLISION_AVOIDANCE_DURATION
          - RADIO_TRANSMIT_CALIBRATION_TIME));

      /* CCAs */
      while(1) {
        NETSTACK_RADIO.async_on();
        schedule_strobe(RTIMER_NOW() + CCA_SLEEP_DURATION);
        PT_YIELD(&pt);
        if(channel_clear(COLLISION_AVOIDANCE)) {
          NETSTACK_RADIO.async_off();
          if(++contikimac_state.strobe.cca_count != CONTIKIMAC_MAX_CCAS) {
            schedule_strobe(RTIMER_NOW() + CONTIKIMAC_INTER_CCA_PERIOD - CONTIKIMAC_LPM_SWITCHING);
            PT_YIELD(&pt);
            /* if we come from PM0, we will be too early */
            while(!rtimer_has_timed_out(timer.time));
            continue;
          }
        } else {
          LOG_INFO("collision\n");
          contikimac_state.strobe.result = MAC_TX_COLLISION;
        }
        break;
      }
      if(contikimac_state.strobe.result == MAC_TX_COLLISION) {
        break;
      }
#endif /* CONTIKIMAC_WITH_INTRA_COLLISION_AVOIDANCE */
    } else {
#if CONTIKIMAC_WITH_INTER_COLLISION_AVOIDANCE
      if(!channel_clear(COLLISION_AVOIDANCE)) {
        LOG_INFO("collision\n");
        contikimac_state.strobe.result = MAC_TX_COLLISION;
        break;
      }
#endif /* CONTIKIMAC_WITH_INTER_COLLISION_AVOIDANCE */
    }

    /* busy waiting for better timing */
    while(!rtimer_has_timed_out(contikimac_state.strobe.next_transmission
        - RADIO_TRANSMIT_CALIBRATION_TIME));

    if(transmit() != RADIO_TX_OK) {
      LOG_ERR("NETSTACK_RADIO.async_transmit failed\n");
      contikimac_state.strobe.result = MAC_TX_ERR;
      break;
    }
    PT_YIELD(&pt);
    contikimac_state.strobe.next_transmission = RTIMER_NOW() + CONTIKIMAC_INTER_FRAME_PERIOD;

    if(contikimac_state.strobe.is_broadcast || !contikimac_state.strobe.strobes /* little tweak */) {
      if(!should_strobe_again()) {
        contikimac_state.strobe.result = MAC_TX_OK;
        break;
      }
      schedule_strobe(contikimac_state.strobe.next_transmission
          - CONTIKIMAC_LPM_SWITCHING
#if CONTIKIMAC_WITH_INTER_COLLISION_AVOIDANCE
          - RADIO_RECEIVE_CALIBRATION_TIME
          - RADIO_CCA_TIME
#endif /* CONTIKIMAC_WITH_INTER_COLLISION_AVOIDANCE */
          - RADIO_TRANSMIT_CALIBRATION_TIME);
      PT_YIELD(&pt);
#if CONTIKIMAC_WITH_INTER_COLLISION_AVOIDANCE
      NETSTACK_RADIO.async_on();
#endif /* CONTIKIMAC_WITH_INTER_COLLISION_AVOIDANCE */
    } else {
      /* wait for acknowledgement */
      schedule_strobe(RTIMER_NOW() + CONTIKIMAC_ACKNOWLEDGEMENT_WINDOW_MAX);
      contikimac_state.strobe.is_waiting_for_acknowledgement_shr = 1;
      PT_YIELD(&pt);
      contikimac_state.strobe.is_waiting_for_acknowledgement_shr = 0;
      if(contikimac_state.strobe.got_acknowledgement_shr) {
        if(NETSTACK_RADIO.async_read_phy_header() != contikimac_state.strobe.acknowledgement_len) {
          LOG_ERR("unexpected frame\n");
          contikimac_state.strobe.result = MAC_TX_COLLISION;
          break;
        }

        /* read acknowledgement */
        if(!NETSTACK_RADIO.async_read_payload(contikimac_state.strobe.acknowledgement, contikimac_state.strobe.acknowledgement_len)) {
          LOG_ERR("could not read acknowledgement\n");
          contikimac_state.strobe.result = MAC_TX_ERR_FATAL;
          break;
        }
        if(!CONTIKIMAC_FRAMER.parse_acknowledgement()) {
          LOG_ERR("invalid acknowledgement\n");
          contikimac_state.strobe.result = MAC_TX_COLLISION;
          break;
        }

        NETSTACK_RADIO.async_off();
        contikimac_state.strobe.result = MAC_TX_OK;
        break;
      }

      /* schedule next transmission */
      if(!should_strobe_again()) {
        contikimac_state.strobe.result = MAC_TX_NOACK;
        break;
      }

      /* go back to sleep if time allows */
      if(schedule_strobe_precise(contikimac_state.strobe.next_transmission
          - CONTIKIMAC_LPM_SWITCHING
          - RADIO_TRANSMIT_CALIBRATION_TIME) == RTIMER_OK) {
        PT_YIELD(&pt);
      }
    }
    contikimac_state.strobe.strobes++;
  }

  if(contikimac_state.strobe.result != MAC_TX_OK) {
    NETSTACK_RADIO.async_off();
  }
  is_strobing = 0;
  process_poll(&post_processing);
  PT_END(&pt);
}
/*---------------------------------------------------------------------------*/
static int
should_strobe_again(void)
{
#if CONTIKIMAC_WITH_SECURE_PHASE_LOCK
  if(contikimac_state.strobe.strobes == 0xFE) {
    LOG_ERR("strobe index reached maximum\n");
    return 0;
  }
#endif /* CONTIKIMAC_WITH_SECURE_PHASE_LOCK */
  return RTIMER_CLOCK_LT_OR_EQ(contikimac_state.strobe.next_transmission - CONTIKIMAC_INTER_FRAME_PERIOD, contikimac_state.strobe.timeout)
      || !contikimac_state.strobe.sent_once_more++;
}
/*---------------------------------------------------------------------------*/
static int
transmit(void)
{
#if CONTIKIMAC_WITH_ORIGINAL_PHASE_LOCK
  contikimac_state.strobe.t0[0] = contikimac_state.strobe.t0[1];
  contikimac_state.strobe.t0[1] = contikimac_state.strobe.next_transmission;
#endif /* CONTIKIMAC_WITH_ORIGINAL_PHASE_LOCK */
  NETSTACK_RADIO.async_transmit(!contikimac_state.strobe.is_broadcast && contikimac_state.strobe.strobes);
  return RADIO_TX_OK;
}
/*---------------------------------------------------------------------------*/
static void
on_strobed(void)
{
  linkaddr_t *receiver;
  struct buffered_frame *next;
  rtimer_clock_t next_attempt;
  uint8_t back_off_exponent;
  uint8_t back_off_periods;

  if(LOG_INFO_ENABLED && !contikimac_state.strobe.is_broadcast) {
    LOG_INFO("strobed %i times with %s\n",
        contikimac_state.strobe.strobes + 1,
        (contikimac_state.strobe.result == MAC_TX_OK) ? "success" : "error");
  }

  queuebuf_to_packetbuf(contikimac_state.strobe.bf->qb);
  if(!contikimac_state.strobe.is_broadcast) {
    CONTIKIMAC_FRAMER.on_unicast_transmitted();
    CONTIKIMAC_SYNCHRONIZER.on_unicast_transmitted();
  }

  switch(contikimac_state.strobe.result) {
  case MAC_TX_COLLISION:
  case MAC_TX_NOACK:
    if(contikimac_state.strobe.bf->transmissions
        >= queuebuf_attr(contikimac_state.strobe.bf->qb, PACKETBUF_ATTR_MAX_MAC_TRANSMISSIONS)) {
      /* intentionally no break; */
    } else {
      /* delay any frames to that receiver */
      back_off_exponent = MIN(contikimac_state.strobe.bf->transmissions + MIN_BACK_OFF_EXPONENT,  MAX_BACK_OFF_EXPONENT);
      back_off_periods = ((1 << back_off_exponent) - 1) & random_rand();
      next_attempt = RTIMER_NOW() + (WAKE_UP_COUNTER_INTERVAL * back_off_periods);

      receiver = queuebuf_addr(contikimac_state.strobe.bf->qb, PACKETBUF_ADDR_RECEIVER);
      next = list_head(buffered_frames_list);
      while(next) {
        if(linkaddr_cmp(receiver, queuebuf_addr(next->qb, PACKETBUF_ADDR_RECEIVER))) {
          next->next_attempt = next_attempt;
        }
        next = list_item_next(next);
      }
      break;
    }
  case MAC_TX_OK:
  case MAC_TX_ERR:
  case MAC_TX_ERR_FATAL:
    queuebuf_free(contikimac_state.strobe.bf->qb);

    mac_call_sent_callback(contikimac_state.strobe.bf->sent,
        contikimac_state.strobe.bf->ptr,
        contikimac_state.strobe.result,
        contikimac_state.strobe.bf->transmissions);
    list_remove(buffered_frames_list, contikimac_state.strobe.bf);
    memb_free(&buffered_frames_memb, contikimac_state.strobe.bf);
    break;
  }
}
/*---------------------------------------------------------------------------*/
static void
send(mac_callback_t sent, void *ptr)
{
#if !AKES_MAC_ENABLED
  packetbuf_set_attr(PACKETBUF_ATTR_FRAME_TYPE, FRAME802154_DATAFRAME);
  packetbuf_set_attr(PACKETBUF_ATTR_MAC_SEQNO, ++mac_dsn);
#endif /* !AKES_MAC_ENABLED */
  queue_frame(sent, ptr);
  try_skip_to_send();
}
/*---------------------------------------------------------------------------*/
static void
try_skip_to_send(void)
{
  if(!skipped && can_skip && rtimer_cancel()) {
    skipped = 1;
  }
}
/*---------------------------------------------------------------------------*/
static void
queue_frame(mac_callback_t sent, void *ptr)
{
  struct buffered_frame *bf;
  struct buffered_frame *next;

  if(!packetbuf_attr(PACKETBUF_ATTR_MAX_MAC_TRANSMISSIONS)) {
    packetbuf_set_attr(PACKETBUF_ATTR_MAX_MAC_TRANSMISSIONS, MAX_RETRANSMISSIONS + 1);
  }

  bf = memb_alloc(&buffered_frames_memb);
  if(!bf) {
    LOG_ERR("buffer is full\n");
    mac_call_sent_callback(sent, ptr, MAC_TX_ERR, 0);
    return;
  }
  bf->qb = queuebuf_new_from_packetbuf();
  if(!bf->qb) {
    LOG_ERR("queubuf is full\n");
    memb_free(&buffered_frames_memb, bf);
    mac_call_sent_callback(sent, ptr, MAC_TX_ERR, 0);
    return;
  }

  bf->ptr = ptr;
  bf->sent = sent;
  bf->transmissions = 0;
  bf->next_attempt = RTIMER_NOW();
  /* do not send earlier than other frames for that receiver */
  next = list_head(buffered_frames_list);
  while(next) {
    if(linkaddr_cmp(packetbuf_addr(PACKETBUF_ADDR_RECEIVER),
        queuebuf_addr(next->qb, PACKETBUF_ADDR_RECEIVER))) {
      bf->next_attempt = next->next_attempt;
      break;
    }
    next = list_item_next(next);
  }
  list_add(buffered_frames_list, bf);
}
/*---------------------------------------------------------------------------*/
static void
input(void)
{
  /* we operate in polling mode throughout */
}
/*---------------------------------------------------------------------------*/
static int
on(void)
{
  /* TODO implement if needed */
  return 1;
}
/*---------------------------------------------------------------------------*/
static int
off(void)
{
  /* TODO implement if needed  */
  return 1;
}
/*---------------------------------------------------------------------------*/
static int
max_payload(void)
{
  return RADIO_MAX_FRAME_LEN - NETSTACK_FRAMER.length();
}
/*---------------------------------------------------------------------------*/
#if CONTIKIMAC_FRAMER_POTR_ILOS_ENABLED
wake_up_counter_t
contikimac_get_wake_up_counter(rtimer_clock_t t)
{
  rtimer_clock_t delta;
  wake_up_counter_t wuc;

  delta = RTIMER_CLOCK_DIFF(t, my_wake_up_counter_last_increment);
  wuc = my_wake_up_counter;
  wuc.u32 += wake_up_counter_increments(delta, NULL);

  return wuc;
}
/*---------------------------------------------------------------------------*/
wake_up_counter_t
contikimac_predict_wake_up_counter(void)
{
  return contikimac_state.strobe.receivers_wake_up_counter;
}
/*---------------------------------------------------------------------------*/
wake_up_counter_t
contikimac_restore_wake_up_counter(void)
{
  struct akes_nbr_entry *entry;
  contikimac_nbr_t *contikimac_nbr;
  rtimer_clock_t delta;
  uint32_t increments;
  uint32_t mod;
  wake_up_counter_t wuc;

  entry = akes_nbr_get_sender_entry();
  if(!entry || !entry->permanent) {
    wuc.u32 = 0;
    LOG_ERR("could not restore wake-up counter\n");
    return wuc;
  }

  contikimac_nbr = contikimac_nbr_get(entry->permanent);
  delta = contikimac_get_last_wake_up_time() - contikimac_nbr->phase.t;
  increments = wake_up_counter_increments(delta, &mod);
  wuc.u32 = contikimac_nbr->phase.his_wake_up_counter_at_t.u32 + increments;

  if(wuc.u32 & 1) {
    /* odd --> we need to round */
    if(mod < (WAKE_UP_COUNTER_INTERVAL / 2)) {
      wuc.u32--;
    } else  {
      wuc.u32++;
    }
  }

  return wuc;
}
#endif /* CONTIKIMAC_FRAMER_POTR_ILOS_ENABLED */
/*---------------------------------------------------------------------------*/
const struct mac_driver contikimac_driver = {
  "ContikiMAC",
  init,
  send,
  input,
  on,
  off,
  max_payload,
};
/*---------------------------------------------------------------------------*/
