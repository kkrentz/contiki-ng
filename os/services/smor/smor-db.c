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
 *         Database of SMOR.
 * \author
 *         Konrad Krentz <konrad.krentz@gmail.com>
 */

#include "smor-db.h"
#include "lib/assert.h"

/* Log configuration */
#include "sys/log.h"
#define LOG_MODULE "SMOR-DB"
#define LOG_LEVEL LOG_LEVEL_RPL

/* to save RAM, we only keep some of the best recent rewards */
#define BEST_REWARDS_COUNT (4)

struct reward {
  smor_db_id_t forwarder_id;
  smor_metric_t reward;
};

struct destination {
  smor_db_bitmap_t tried_neighbors;
  struct reward best_rewards[BEST_REWARDS_COUNT];
};

static struct destination destinations[SMOR_DB_MAX_NODES - 1];
static linkaddr_t addresses[SMOR_DB_MAX_NODES - 1];
static smor_db_bitmap_t adjacency_lists[SMOR_DB_MAX_NODES - 1];
const smor_db_id_t smor_db_my_id = SMOR_DB_MAX_NODES - 1;

/*---------------------------------------------------------------------------*/
static void
reset_reward(struct reward *reward)
{
  reward->forwarder_id = SMOR_DB_INVALID_ID;
  reward->reward = SMOR_METRIC.get_min();
}
/*---------------------------------------------------------------------------*/
void
smor_db_init(void)
{
  for(smor_db_id_t i = 0; i < smor_db_my_id; i++) {
    for(size_t j = 0; j < BEST_REWARDS_COUNT; j++) {
      reset_reward(destinations[i].best_rewards + j);
    }
  }
}
/*---------------------------------------------------------------------------*/
smor_db_id_t
smor_db_get_id(const linkaddr_t *addr)
{
  if(linkaddr_cmp(addr, &linkaddr_node_addr)) {
    return smor_db_my_id;
  }
  for(smor_db_id_t i = 0; i < smor_db_my_id; i++) {
    if(linkaddr_cmp(addresses + i, addr)) {
      return i;
    }
  }
  return SMOR_DB_INVALID_ID;
}
/*---------------------------------------------------------------------------*/
const linkaddr_t *
smor_db_get_address(smor_db_id_t id)
{
  assert(id <= smor_db_my_id);

  return id == smor_db_my_id ? &linkaddr_node_addr : addresses + id;
}
/*---------------------------------------------------------------------------*/
smor_db_id_t
smor_db_get_or_create_id(const linkaddr_t *addr)
{
  smor_db_id_t id = smor_db_get_id(addr);
  if(id != SMOR_DB_INVALID_ID) {
    return id;
  }
  id = smor_db_get_id(&linkaddr_null);
  if(id != SMOR_DB_INVALID_ID) {
    linkaddr_copy(addresses + id, addr);
  }
  /* TODO deletion strategy */
  return id;
}
/*---------------------------------------------------------------------------*/
smor_db_bitmap_t
smor_db_get_adjacency_list(smor_db_id_t id)
{
  assert(id <= smor_db_my_id);

  if(id == smor_db_my_id) {
    uint32_t my_adjacency_list = 0;
    for(smor_db_id_t i = 0; i < smor_db_my_id - 1; i++) {
      if(smor_db_have_link(smor_db_my_id, i)) {
        my_adjacency_list |= 1ul << i;
      }
    }
    return my_adjacency_list;
  }
  return adjacency_lists[id];
}
/*---------------------------------------------------------------------------*/
void
smor_db_add_link(smor_db_id_t from, smor_db_id_t to)
{
  assert(from <= smor_db_my_id);
  assert(to <= smor_db_my_id);

  if(from != smor_db_my_id) {
    adjacency_lists[from] |= 1ul << to;
  }
  if(to != smor_db_my_id) {
    adjacency_lists[to] |= 1ul << from;
  }
}
/*---------------------------------------------------------------------------*/
void
smor_db_cut_link(smor_db_id_t from, smor_db_id_t to)
{
  assert(from <= smor_db_my_id);
  assert(to <= smor_db_my_id);

  if(from != smor_db_my_id) {
    adjacency_lists[from] &= ~(1ul << to);
  }
  if(to != smor_db_my_id) {
    adjacency_lists[to] &= ~(1ul << from);
  }
}
/*---------------------------------------------------------------------------*/
void
smor_db_set_links(smor_db_id_t id, smor_db_bitmap_t bitmap)
{
  for(smor_db_id_t i = 0; i < smor_db_my_id; i++) {
    if(bitmap & (1ul << i)) {
      smor_db_add_link(id, i);
    } else {
      smor_db_cut_link(id, i);
    }
  }
}
/*---------------------------------------------------------------------------*/
bool
smor_db_have_link(smor_db_id_t from, smor_db_id_t to)
{
  if(from == to) {
    return true;
  } else if(from == smor_db_my_id) {
    return adjacency_lists[to] & (1ul << from);
  } else {
    return adjacency_lists[from] & (1ul << to);
  }
}
/*---------------------------------------------------------------------------*/
void
smor_db_store_forwarders_reward(smor_db_id_t destination_id,
                                smor_db_id_t forwarder_id,
                                smor_metric_t reward)
{
  assert(destination_id < smor_db_my_id);
  assert(forwarder_id < smor_db_my_id);

  struct destination *destination = destinations + destination_id;
  destination->tried_neighbors |= 1ul << forwarder_id;

  /* replace previous reward if existing */
  for(size_t i = 0; i < BEST_REWARDS_COUNT; i++) {
    if(destination->best_rewards[i].forwarder_id == forwarder_id) {
      destination->best_rewards[i].reward = reward;
      return;
    }
  }

  /* find worst forwarder */
  smor_metric_t worst_path_metric;
  size_t worst_slot = 0;
  for(size_t i = 0; i < BEST_REWARDS_COUNT; i++) {
    smor_metric_t path_metric = destination->best_rewards[i].reward;
    if(path_metric != SMOR_METRIC.get_min()) {
      path_metric = SMOR_METRIC.judge_path(
                        SMOR_METRIC.judge_link_to(
                            smor_db_get_address(
                                destination->best_rewards[i].forwarder_id)),
                        path_metric);
    }

    if(!i) {
      worst_path_metric = path_metric;
    } else if(SMOR_METRIC.better_than(worst_path_metric, path_metric)) {
      worst_path_metric = path_metric;
      worst_slot = i;
    }
  }

  /* overwrite worst forwarder when better */
  smor_metric_t path_metric =
      SMOR_METRIC.judge_path(
          SMOR_METRIC.judge_link_to(smor_db_get_address(forwarder_id)),
          reward);
  if(SMOR_METRIC.better_than(path_metric, worst_path_metric)) {
    destination->best_rewards[worst_slot].reward = reward;
    destination->best_rewards[worst_slot].forwarder_id = forwarder_id;
  }
}
/*---------------------------------------------------------------------------*/
smor_metric_t
smor_db_get_forwarders_reward(smor_db_id_t destination_id,
                              smor_db_id_t forwarder_id)
{
  assert(destination_id < smor_db_my_id);
  assert(forwarder_id < smor_db_my_id);
  assert(destination_id != forwarder_id);

  struct destination *destination = destinations + destination_id;
  if(!(destination->tried_neighbors & (1ul << forwarder_id))) {
    return SMOR_METRIC.get_max();
  }
  for(size_t i = 0; i < BEST_REWARDS_COUNT; i++) {
    if(destination->best_rewards[i].forwarder_id == forwarder_id) {
      return destination->best_rewards[i].reward;
    }
  }
  return SMOR_METRIC.get_min();
}
/*---------------------------------------------------------------------------*/
void
smor_db_on_new_neighbor(akes_nbr_entry_t *entry)
{
  smor_db_id_t neighbor_id =
      smor_db_get_or_create_id(akes_nbr_get_addr(entry));
  if(neighbor_id == SMOR_DB_INVALID_ID) {
    LOG_ERR("smor_db_get_or_create_id failed\n");
    return;
  }
  smor_db_add_link(smor_db_my_id, neighbor_id);
}
/*---------------------------------------------------------------------------*/
void
smor_db_on_neighbor_lost(akes_nbr_entry_t *entry)
{
  smor_db_id_t neighbor_id = smor_db_get_id(akes_nbr_get_addr(entry));
  if(neighbor_id == SMOR_DB_INVALID_ID) {
    LOG_ERR("smor_db_get_id failed\n");
    return;
  }
  smor_db_cut_link(smor_db_my_id, neighbor_id);
  for(smor_db_id_t i = 0; i < smor_db_my_id; i++) {
    struct destination *destination = destinations + i;
    destination->tried_neighbors &= ~(1ul << neighbor_id);
    for(size_t j = 0; j < BEST_REWARDS_COUNT; j++) {
      if(destination->best_rewards[j].forwarder_id == neighbor_id) {
        reset_reward(destination->best_rewards + j);
        break;
      }
    }
  }
}
/*---------------------------------------------------------------------------*/
