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
 * \file
 *         HPI-MAC integration.
 * \author
 *         Konrad Krentz <konrad.krentz@gmail.com>
 */

#include "contiki.h"
#include "lib/assert.h"
#include "lib/random.h"
#include "net/ipv6/sicslowpan.h"
#include "net/mac/csl/csl-nbr.h"
#include "net/mac/csl/csl-synchronizer-splo.h"
#include "net/mac/csl/csl-synchronizer.h"
#include "net/mac/csl/csl.h"
#include "net/packetbuf.h"
#include "net/queuebuf.h"
#include "smor-db.h"
#include "smor-l2.h"
#include <stddef.h>

/* Log configuration */
#include "sys/log.h"
#define LOG_MODULE "SMOR-L2"
#define LOG_LEVEL LOG_LEVEL_RPL

#ifdef SMOR_L2_CONF_EPSILON
#define EPSILON SMOR_L2_CONF_EPSILON
#else /* SMOR_L2_CONF_EPSILON */
#define EPSILON (1) /* % */
#endif /* SMOR_L2_CONF_EPSILON */

static bool is_one_hop_frame(void);
static size_t select_two_hop_forwarders(frame_queue_forwarder_t *forwarders,
                                        size_t max_forwarders,
                                        const linkaddr_t *forwarder_to_exclude,
                                        const linkaddr_t *dest);
static int schedule_one_hop_frame(void);
static int schedule_two_hop_frame(void);

/*---------------------------------------------------------------------------*/
static void
init(void)
{
  SMOR_METRIC.init();
  smor_db_init();
  csl_synchronizer_splo.init();
}
/*---------------------------------------------------------------------------*/
bool
smor_l2_select_forwarders(
    frame_queue_forwarder_t forwarders[static FRAME_QUEUE_MAX_FORWARDERS])
{
  const linkaddr_t *dest = packetbuf_addr(PACKETBUF_ADDR_RECEIVER);
  size_t forwarders_count;
  if(is_one_hop_frame()) {
    linkaddr_copy(&forwarders[0].addr, dest);
    forwarders[0].tried = false;
    forwarders_count = 1;
  } else {
    forwarders_count = select_two_hop_forwarders(forwarders,
                                                 FRAME_QUEUE_MAX_FORWARDERS,
                                                 &linkaddr_null,
                                                 dest);
  }
  for(size_t forwarder_index = forwarders_count;
      forwarder_index < FRAME_QUEUE_MAX_FORWARDERS;
      forwarder_index++) {
    linkaddr_copy(&forwarders[forwarder_index].addr, &linkaddr_null);
    forwarders[forwarder_index].tried = false;
  }
  return forwarders_count != 0;
}
/*---------------------------------------------------------------------------*/
bool
smor_l2_select_spare_forwarder(frame_queue_forwarder_t *spare_forwarder,
                               const linkaddr_t *dest,
                               const linkaddr_t *forwarder_to_exclude)
{
  return 0 != select_two_hop_forwarders(spare_forwarder,
                                        1,
                                        forwarder_to_exclude,
                                        dest);
}
/*---------------------------------------------------------------------------*/
static bool
is_one_hop_frame(void)
{
  return packetbuf_holds_cmd_frame()
         || ((packetbuf_get_dispatch_byte() & SICSLOWPAN_DISPATCH_MESH_MASK)
             != SICSLOWPAN_DISPATCH_MESH)
         || ((packetbuf_get_dispatch_byte() & SICSLOWPAN_MESH_HOPS_LEFT) <= 1);
}
/*---------------------------------------------------------------------------*/
/* TODO move to random.c for reuse elsewhere */
static uint16_t
generate_random_uint16(uint16_t max)
{
  uint16_t result;

  /* sort out special cases */
  switch(max) {
  case 0:
    return 0;
  case UINT16_MAX:
    return random_rand();
  case UINT8_MAX:
    return random_rand() & UINT8_MAX;
  default:
    break;
  }

  {
    bool has_overflowed;
    uint16_t lower_half;
    uint16_t upper_half;

    if(max > UINT8_MAX) {
      has_overflowed = true;
      lower_half = max & UINT8_MAX;
      upper_half = max & ~UINT8_MAX;
      max >>= (sizeof(uint16_t) / 2) * 8;
    } else {
      has_overflowed = false;
    }

    /* along the lines of https://jacquesheunis.com/post/bounded-random/ */
    max++; /* in order to get results <= max */
    result = (random_rand() & UINT8_MAX) * max;
    if((result & UINT8_MAX) < max) {
      uint16_t min_valid_value = (UINT8_MAX + 1) % max;
      while((result & UINT8_MAX) < min_valid_value) {
        result = (random_rand() & UINT8_MAX) * max;
      }
    }

    if(!has_overflowed) {
      return result >> ((sizeof(uint16_t) / 2) * 8);
    }

    result &= ~UINT8_MAX;
    result |= result < upper_half
              ? random_rand() & UINT8_MAX
              : generate_random_uint16(lower_half);
  }
  return result;
}
/*---------------------------------------------------------------------------*/
static size_t
select_two_hop_forwarders(frame_queue_forwarder_t *forwarders,
                          size_t max_forwarders,
                          const linkaddr_t *forwarder_to_exclude,
                          const linkaddr_t *dest)
{
  smor_db_id_t destination_id = smor_db_get_or_create_id(dest);
  if(destination_id == SMOR_DB_INVALID_ID) {
    LOG_ERR("smor_db_get_or_create_id failed\n");
    return 0;
  }

  size_t forwarders_count = 0;
  bool first_round = true;
  uint_fast8_t trial_path = 0;
  smor_metric_t best_path_metrics[FRAME_QUEUE_MAX_FORWARDERS];
  while(1) {
    uint_fast8_t path_count = 0;
    for(akes_nbr_entry_t *entry = akes_nbr_head(AKES_NBR_PERMANENT);
        entry;
        entry = akes_nbr_next(entry, AKES_NBR_PERMANENT)) {
      const linkaddr_t *forwarder_addr = akes_nbr_get_addr(entry);
      if(linkaddr_cmp(forwarder_to_exclude, forwarder_addr)) {
        continue;
      }
      smor_db_id_t forwarder_id = smor_db_get_id(forwarder_addr);
      if(forwarder_id == SMOR_DB_INVALID_ID) {
        continue;
      }
      if(!smor_db_have_link(forwarder_id, destination_id)) {
        continue;
      }
      path_count++;
      if(first_round) {
        continue;
      }

      smor_metric_t path_metric;
      if(path_count == trial_path) {
        /* epsilon-greedy */
        LOG_DBG("Exploring forwarder ");
        LOG_DBG_LLADDR(forwarder_addr);
        LOG_DBG_("\n");
        path_metric = SMOR_METRIC.get_max();
      } else {
        path_metric = SMOR_METRIC.judge_link_to(akes_nbr_get_addr(entry));
        if(forwarder_id != destination_id) {
          smor_metric_t latest_reward =
              smor_db_get_forwarders_reward(destination_id, forwarder_id);
          path_metric = SMOR_METRIC.judge_path(path_metric, latest_reward);
        }
      }

      bool inserted = false;
      for(size_t i = 0; i < forwarders_count; i++) {
        if(SMOR_METRIC.better_than(path_metric, best_path_metrics[i])) {
          memmove(forwarders + i + 1,
                  forwarders + i,
                  MIN(forwarders_count - i, max_forwarders - i - 1)
                  * sizeof(forwarders[0]));
          memmove(best_path_metrics + i + 1,
                  best_path_metrics + i,
                  MIN(forwarders_count - i, max_forwarders - i - 1)
                  * sizeof(best_path_metrics[0]));
          linkaddr_copy(&forwarders[i].addr, forwarder_addr);
          forwarders[i].tried = false;
          best_path_metrics[i] = path_metric;
          inserted = true;
          break;
        }
      }
      if(!inserted && (forwarders_count < max_forwarders)) {
        linkaddr_copy(&forwarders[forwarders_count].addr, forwarder_addr);
        forwarders[forwarders_count].tried = false;
        best_path_metrics[forwarders_count] = path_metric;
      }
      forwarders_count = MIN(forwarders_count + 1, max_forwarders);
    }
    if(!first_round) {
      break;
    }
    if(!path_count) {
      LOG_WARN("no paths to destination\n");
      return 0;
    }
    if(random_rand() <= ((((uint32_t)RANDOM_RAND_MAX) * EPSILON) / 100)) {
      trial_path = generate_random_uint16(path_count - 1) + 1;
    }
    first_round = false;
  }

  if(forwarders_count
     && linkaddr_cmp(dest, &forwarders[0].addr)
     && (SMOR_METRIC.get_max() != best_path_metrics[0])) {
    /* ignore alternative paths if the direct path is best */
    forwarders_count = 1;
  }

  return forwarders_count;
}
/*---------------------------------------------------------------------------*/
static int
schedule(void)
{
  if(is_one_hop_frame()) {
    return schedule_one_hop_frame();
  } else {
    return schedule_two_hop_frame();
  }
}
/*---------------------------------------------------------------------------*/
static int
schedule_one_hop_frame(void)
{
  linkaddr_copy(&csl_state.transmit.next_hop_address,
                packetbuf_addr(PACKETBUF_ADDR_RECEIVER));
  return csl_synchronizer_splo.schedule();
}
/*---------------------------------------------------------------------------*/
static int
schedule_two_hop_frame(void)
{
  bool scheduled = false;
  rtimer_clock_t earliest_payload_frame_start;
  rtimer_clock_t earliest_wake_up_sequence_start;
  uint16_t earliest_remaining_wake_up_frames;
  wake_up_counter_t earliest_receivers_wake_up_counter;

  for(size_t i = 0; i < FRAME_QUEUE_MAX_FORWARDERS; i++) {
    if(csl_state.transmit.fqe[0]->forwarders[i].tried) {
      continue;
    }
    const linkaddr_t *addr = &csl_state.transmit.fqe[0]->forwarders[i].addr;
    packetbuf_set_addr(PACKETBUF_ADDR_RECEIVER, addr);
    if(packetbuf_holds_broadcast()) {
      continue;
    }
    if(frame_queue_is_backing_off(addr)) {
      continue;
    }
    if(!csl_nbr_get_receiver()) {
      LOG_WARN("forwarder lost\n");
      linkaddr_copy(&csl_state.transmit.next_hop_address, addr);
      return MAC_TX_FORWARDER_LOST;
    }
    int result = csl_synchronizer_splo.schedule();
    if(result != MAC_TX_OK) {
      linkaddr_copy(&csl_state.transmit.next_hop_address, addr);
      return result;
    }

    /* store result if earlier */
    if(!scheduled
       || (RTIMER_CLOCK_LT(csl_state.transmit.payload_frame_start,
                           earliest_payload_frame_start))) {
      earliest_payload_frame_start =
          csl_state.transmit.payload_frame_start;
      earliest_wake_up_sequence_start =
          csl_state.transmit.wake_up_sequence_start;
      earliest_remaining_wake_up_frames =
          csl_state.transmit.remaining_wake_up_frames;
      earliest_receivers_wake_up_counter =
          csl_state.transmit.receivers_wake_up_counter;
      linkaddr_copy(&csl_state.transmit.next_hop_address, addr);
      scheduled = true;
    }
  }

  assert(scheduled);

  /* restore the earliest possibility */
  csl_state.transmit.remaining_wake_up_frames =
      earliest_remaining_wake_up_frames;
  csl_state.transmit.payload_frame_start =
      earliest_payload_frame_start;
  csl_state.transmit.wake_up_sequence_start =
      earliest_wake_up_sequence_start;
  csl_state.transmit.receivers_wake_up_counter =
      earliest_receivers_wake_up_counter;

  LOG_DBG("Forwarding to ");
  LOG_DBG_LLADDR(&csl_state.transmit.next_hop_address);
  LOG_DBG_("\n");

  return MAC_TX_OK;
}
/*---------------------------------------------------------------------------*/
static void
on_unicast_transmitted(bool successful, uint_fast8_t burst_index)
{
  csl_synchronizer_splo.on_unicast_transmitted(successful, burst_index);
  if(!successful
     || !csl_state.transmit.has_mesh_header[burst_index]
     || csl_state.transmit.on_last_hop[burst_index]) {
    return;
  }

  const linkaddr_t *destination_addr =
      queuebuf_addr(csl_state.transmit.fqe[burst_index]->qb,
                    PACKETBUF_ADDR_RECEIVER);
  smor_db_id_t destination_id = smor_db_get_id(destination_addr);
  if(destination_id == SMOR_DB_INVALID_ID) {
    LOG_ERR("smor_db_get_id failed\n");
    assert(false);
    return;
  }
  smor_db_id_t forwarder_id =
      smor_db_get_id(packetbuf_addr(PACKETBUF_ADDR_RECEIVER));
  if(forwarder_id == SMOR_DB_INVALID_ID) {
    LOG_ERR("get_id failed\n");
    assert(false);
    return;
  }
  smor_db_store_forwarders_reward(destination_id,
                                  forwarder_id,
                                  csl_state.transmit.reward[burst_index]);
  if(csl_state.transmit.reward[burst_index] == SMOR_METRIC.get_min()) {
    smor_db_cut_link(forwarder_id, destination_id);
  }
}
/*---------------------------------------------------------------------------*/
void
smor_l2_on_outgoing_frame_loaded(uint_fast8_t burst_index)
{
  packetbuf_set_addr(PACKETBUF_ADDR_RECEIVER,
                     &csl_state.transmit.next_hop_address);
  csl_state.transmit.has_mesh_header[burst_index] =
      packetbuf_holds_data_frame()
      && ((packetbuf_get_dispatch_byte() & SICSLOWPAN_DISPATCH_MESH_MASK)
          == SICSLOWPAN_DISPATCH_MESH);
  csl_state.transmit.on_last_hop[burst_index] =
      linkaddr_cmp(&csl_state.transmit.next_hop_address,
                   queuebuf_addr(csl_state.transmit.fqe[burst_index]->qb,
                                 PACKETBUF_ADDR_RECEIVER));
}
/*---------------------------------------------------------------------------*/
bool
smor_l2_fits_burst(frame_queue_entry_t *fqe)
{
  for(size_t forwarder_index = 0;
      forwarder_index < FRAME_QUEUE_MAX_FORWARDERS;
      forwarder_index++) {
    if(fqe->forwarders[forwarder_index].tried) {
      continue;
    }
    if(linkaddr_cmp(packetbuf_addr(PACKETBUF_ADDR_RECEIVER),
                    &fqe->forwarders[forwarder_index].addr)) {
      return true;
    }
  }
  return false;
}
/*---------------------------------------------------------------------------*/
const struct csl_synchronizer smor_l2_synchronizer = {
  init,
  schedule,
  on_unicast_transmitted,
};
/*---------------------------------------------------------------------------*/
