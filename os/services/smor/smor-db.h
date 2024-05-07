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

#ifndef SMOR_DB_H_
#define SMOR_DB_H_

#include "net/linkaddr.h"
#include "net/nbr-table.h"
#include "services/akes/akes-nbr.h"
#include "smor-metric.h"
#include <stdbool.h>
#include <stdint.h>

#define SMOR_DB_MAX_NODES (32)
#define SMOR_DB_INVALID_ID (UINT16_MAX)
#define SMOR_DB_BITMAP_MAX (UINT32_MAX)

typedef uint32_t smor_db_bitmap_t;
typedef uint16_t smor_db_id_t;

#if NBR_TABLE_MAX_NEIGHBORS > SMOR_DB_MAX_NODES
#error "NBR_TABLE_MAX_NEIGHBORS > SMOR_DB_MAX_NODES"
#endif

void smor_db_init(void);
smor_db_id_t smor_db_get_id(const linkaddr_t *addr);
const linkaddr_t *smor_db_get_address(smor_db_id_t id);
smor_db_id_t smor_db_get_or_create_id(const linkaddr_t *addr);
void smor_db_add_link(smor_db_id_t from, smor_db_id_t to);
void smor_db_cut_link(smor_db_id_t from, smor_db_id_t to);
bool smor_db_have_link(smor_db_id_t from, smor_db_id_t to);
void smor_db_set_links(smor_db_id_t id, smor_db_bitmap_t bitmap);
smor_db_bitmap_t smor_db_get_adjacency_list(smor_db_id_t id);

void smor_db_store_forwarders_reward(smor_db_id_t destination_id,
                                     smor_db_id_t forwarder_id,
                                     smor_metric_t reward);
smor_metric_t smor_db_get_forwarders_reward(smor_db_id_t destination_id,
                                            smor_db_id_t forwarder_id);

/**
 * \brief To be called when a permanent neighbor was added.
 */
void smor_db_on_new_neighbor(akes_nbr_entry_t *entry);

/**
 * \brief To be called when a permanent neighbor was deleted.
 */
void smor_db_on_neighbor_lost(akes_nbr_entry_t *entry);

extern const smor_db_id_t smor_db_my_id;

#endif /* SMOR_DB_H_ */
