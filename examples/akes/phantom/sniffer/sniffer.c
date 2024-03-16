/*
 * Copyright (c) 2021, Uppsala universitet.
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

#include "contiki.h"
#include "net/netstack.h"
#include "net/mac/mac.h"
#include "dev/radio.h"
#include "dev/cc2538-rf.h"
#include "net/mac/wake-up-counter.h"
#include <stdio.h>

#define REQUIRED_HEADER_BYTES (1 /* frame type */ \
    + 1 /* sequence number */ \
    + 1 /* pending frame's length */ \
    + 4 /* counter */)
#define MAX_BURST 5

static void switch_channel(struct rtimer *rt, void *ptr);

PROCESS(sniffer_process, "sniffer_process");
AUTOSTART_PROCESSES(&sniffer_process);
static const uint8_t channels[] = { 11 , 12 , 13 , 14 , 15 , 16 , 17 , 18 , 19 , 20 , 21 , 22 , 23 , 24 , 25 , 26 };
static uint32_t payload_frame_counter[MAX_BURST];
static clock_time_t payload_frame_timestamp[MAX_BURST];
static clock_time_t acknowledgment_frame_timestamp[MAX_BURST];
static int8_t payload_frame_rssi[MAX_BURST];
static int8_t acknowledgment_frame_rssi[MAX_BURST];
static struct rtimer timer;
static int channel_hopping_started;
static uint8_t current_channel_mask;
static const uint8_t bobs_channel_mask = 0xf5;
static rtimer_clock_t next_switch_time;
static uint8_t current_channel;
static const char name[] = "E1";
static rtimer_clock_t last_shr_timestamp;
static int received_payload_frame[MAX_BURST];
static int received_acknowledgment_frame[MAX_BURST];
static uint8_t burst_index;

/*---------------------------------------------------------------------------*/
static int
schedule(rtimer_clock_t time)
{
  timer.time = time;
  timer.func = switch_channel;
  timer.ptr = NULL;
  return rtimer_set_precise(&timer);
}
/*---------------------------------------------------------------------------*/
static void
switch_channel(struct rtimer *rt, void *ptr)
{
  uint8_t i;
  NETSTACK_RADIO.async_off();
  CC2538_RF_CSP_ISFLUSHRX();

  for(i = 0; i < MAX_BURST; i++) {
    if(received_payload_frame[i]) {
      printf("%s,PING,%lu,%u,%lu,%i,%u\n",
          name,
          payload_frame_timestamp[i],
          current_channel,
          payload_frame_counter[i],
          payload_frame_rssi[i],
          MAC_TX_OK);
      if(received_acknowledgment_frame[i] && (acknowledgment_frame_timestamp[i] - payload_frame_timestamp[i] <= 1)) {
        printf("%s,PONG,%lu,%u,%lu,%i,%u\n",
            name,
            acknowledgment_frame_timestamp[i],
            current_channel,
            payload_frame_counter[i],
            acknowledgment_frame_rssi[i],
            MAC_TX_OK);
      }
    }
  }

  do {
    current_channel = channels[(bobs_channel_mask ^ ++current_channel_mask) & (sizeof(channels) - 1)];
    next_switch_time += WAKE_UP_COUNTER_INTERVAL;
  } while(schedule(next_switch_time) != RTIMER_OK);

  NETSTACK_RADIO.set_value(RADIO_PARAM_CHANNEL, current_channel);
  NETSTACK_RADIO.async_on();
  for(i = 0; i < MAX_BURST; i++) {
    received_payload_frame[i] = 0;
    received_acknowledgment_frame[i] = 0;
  }
  burst_index = 0;
}
/*---------------------------------------------------------------------------*/
static void
on_final_payload_frame_fifop(void)
{
  NETSTACK_RADIO.async_set_fifop_callback(NULL, 0);
  payload_frame_rssi[burst_index] = radio_get_rssi();
  CC2538_RF_CSP_ISFLUSHRX();
  payload_frame_timestamp[burst_index] = clock_time();
}
/*---------------------------------------------------------------------------*/
static void
on_payload_frame_fifop(void)
{
  uint8_t buf[REQUIRED_HEADER_BYTES];

  NETSTACK_RADIO.async_set_fifop_callback(NULL, RADIO_MAX_PAYLOAD);
  NETSTACK_RADIO.async_read_payload(buf, REQUIRED_HEADER_BYTES);
  if((buf[0] & 0xFE) != 0x36) {
    CC2538_RF_CSP_ISFLUSHRX();
    return;
  }
  if(!channel_hopping_started) {
    channel_hopping_started = 1;
    next_switch_time = last_shr_timestamp + (WAKE_UP_COUNTER_INTERVAL/2);
    schedule(next_switch_time);
  }
  if(received_payload_frame[burst_index]) {
    burst_index++;
  }
  received_payload_frame[burst_index] = 1;
  memcpy(&payload_frame_counter[burst_index],
      buf + 1 + 1 + ((buf[0] & (1 << 7)) ? 1 : 0),
      sizeof(payload_frame_counter[0]));
  NETSTACK_RADIO.async_set_fifop_callback(on_final_payload_frame_fifop,
      radio_remaining_payload_bytes());
}
/*---------------------------------------------------------------------------*/
static void
on_shr(void)
{
  uint8_t frame_len;

  frame_len = NETSTACK_RADIO.async_read_phy_header();
  switch(frame_len) {
  case 11:
    /* acknowledgment frames */
    CC2538_RF_CSP_ISFLUSHRX();
    if(channel_hopping_started && received_payload_frame[burst_index]) {
      acknowledgment_frame_timestamp[burst_index] = clock_time();
      acknowledgment_frame_rssi[burst_index] = radio_get_rssi();
      received_acknowledgment_frame[burst_index] = 1;
    }
    break;
  case 14:
  case 15:
    /* payload frames */
    NETSTACK_RADIO.async_set_fifop_callback(on_payload_frame_fifop,
        1 /* Frame Length */ + REQUIRED_HEADER_BYTES);
    last_shr_timestamp = RTIMER_NOW();
    break;
  default:
    CC2538_RF_CSP_ISFLUSHRX();
    break;
  }
}
/*---------------------------------------------------------------------------*/
PROCESS_THREAD(sniffer_process, ev, data)
{

  PROCESS_BEGIN();

  printf("%s started\n", name);
  printf("ticks %u per second\n", CLOCK_SECOND);
  printf("receiver,msg,time,channel,seq,rssi,status\n");

  current_channel = IEEE802154_DEFAULT_CHANNEL;
  NETSTACK_RADIO.async_enter();
  NETSTACK_RADIO.set_value(RADIO_PARAM_CHANNEL, current_channel);
  NETSTACK_RADIO.async_set_shr_callback(on_shr);
  NETSTACK_RADIO.async_on();

  PROCESS_END();
}
/*---------------------------------------------------------------------------*/
