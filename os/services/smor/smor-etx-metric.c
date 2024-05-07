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
 */

/**
 * \file
 *         Imports ETX from the link-stats.module.
 * \author
 *         Konrad Krentz <konrad.krentz@gmail.com>
 */

#include "net/link-stats.h"
#include "services/akes/akes-nbr.h"
#include "smor-metric.h"
#include <sys/types.h>

/* Log configuration */
#include "sys/log.h"
#define LOG_MODULE "SMOR-ETX"
#define LOG_LEVEL LOG_LEVEL_RPL

/*---------------------------------------------------------------------------*/
static void
init(void)
{
  link_stats_init();
}
/*---------------------------------------------------------------------------*/
static smor_metric_t
get_max(void)
{
  return 0;
}
/*---------------------------------------------------------------------------*/
static smor_metric_t
get_min(void)
{
  return UINT16_MAX;
}
/*---------------------------------------------------------------------------*/
static smor_metric_t
judge_link_to(const linkaddr_t *addr)
{
  struct akes_nbr_entry *one_hop_entry = akes_nbr_get_entry(addr);
  if(!one_hop_entry || !one_hop_entry->permanent) {
    return get_min();
  }
  const struct link_stats *stats = link_stats_from_lladdr(addr);
  if(!stats || !stats->etx) {
    LOG_WARN("returning default ETX\n");
    return LINK_STATS_ETX_DIVISOR * 2;
  }
  return stats->etx;
}
/*---------------------------------------------------------------------------*/
static smor_metric_t
judge_path(smor_metric_t first_hop_etx, smor_metric_t second_hop_etx)
{
  return first_hop_etx + second_hop_etx;
}
/*---------------------------------------------------------------------------*/
static bool
better_than(smor_metric_t this_etx, smor_metric_t that_etx)
{
  return this_etx < that_etx;
}
/*---------------------------------------------------------------------------*/
const struct smor_metric smor_etx_metric = {
  init,
  get_max,
  get_min,
  judge_link_to,
  judge_path,
  better_than,
};
/*---------------------------------------------------------------------------*/
