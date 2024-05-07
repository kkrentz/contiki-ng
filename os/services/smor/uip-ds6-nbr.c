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
 *         Tailors the original uip-ds6-nbr.c to SMOR.
 * \author
 *         Konrad Krentz <konrad.krentz@gmail.com>
 */

#include "lib/assert.h"
#include "net/ipv6/sicslowpan.h"
#include "net/ipv6/uip-ds6-nbr.h"
#include "net/ipv6/uip-ds6.h"
#include "net/link-stats.h"
#include "net/linkaddr.h"
#include "smor-db.h"
#include <stdbool.h>

/* Log configuration */
#include "sys/log.h"
#define LOG_MODULE "uip-ds6-nbr"
#define LOG_LEVEL LOG_LEVEL_IPV6

/*---------------------------------------------------------------------------*/
void
uip_ds6_neighbors_init(void)
{
}
/*---------------------------------------------------------------------------*/
int
uip_ds6_nbr_update_ll(uip_ds6_nbr_t **nbr_pp, const uip_lladdr_t *new_ll_addr)
{
  LOG_ERR("uip_ds6_nbr_update_ll called\n");
  assert(false);
  return 0;
}
/*---------------------------------------------------------------------------*/
const uip_ipaddr_t *
uip_ds6_nbr_get_ipaddr(const uip_ds6_nbr_t *nbr)
{
  return nbr ? &nbr->ipaddr : NULL;
}
/*---------------------------------------------------------------------------*/
const uip_lladdr_t *
uip_ds6_nbr_get_ll(const uip_ds6_nbr_t *nbr)
{
  static uip_lladdr_t lladdr;
  uip_ds6_set_lladdr_from_iid(&lladdr, uip_ds6_nbr_get_ipaddr(nbr));
  return &lladdr;
}
/*---------------------------------------------------------------------------*/
int
uip_ds6_nbr_num(void)
{
  LOG_ERR("uip_ds6_nbr_num called\n");
  assert(false);
  return 0;
}
/*---------------------------------------------------------------------------*/
uip_ds6_nbr_t *
uip_ds6_nbr_head(void)
{
  LOG_ERR("uip_ds6_nbr_head called\n");
  assert(false);
  return NULL;
}
/*---------------------------------------------------------------------------*/
uip_ds6_nbr_t *
uip_ds6_nbr_next(uip_ds6_nbr_t *nbr)
{
  LOG_ERR("uip_ds6_nbr_next called\n");
  assert(false);
  return NULL;
}
/*---------------------------------------------------------------------------*/
/* called by tcpip.c to get the uip_ds6_nbr_t of the selected next hop */
uip_ds6_nbr_t *
uip_ds6_nbr_lookup(const uip_ipaddr_t *ipaddr)
{
#if UIP_LLADDR_LEN == 2
  if(!sicslowpan_is_iid_16_bit_compressable(ipaddr)) {
    return NULL;
  }
#endif /* UIP_LLADDR_LEN == 2 */
  uip_lladdr_t lladdr;
  uip_ds6_set_lladdr_from_iid(&lladdr, ipaddr);
  return uip_ds6_nbr_ll_lookup(&lladdr);
}
/*---------------------------------------------------------------------------*/
uip_ds6_nbr_t *
uip_ds6_nbr_ll_lookup(const uip_lladdr_t *lladdr)
{
  if(smor_db_get_id((const linkaddr_t *)lladdr) == SMOR_DB_INVALID_ID) {
    return NULL;
  }
  static uip_ds6_nbr_t nbr;
  nbr.isrouter = 1;
  nbr.state = NBR_REACHABLE;
  uip_create_linklocal_prefix(&nbr.ipaddr);
  uip_ds6_set_addr_iid(&nbr.ipaddr, lladdr);
  return &nbr;
}
/*---------------------------------------------------------------------------*/
uip_ipaddr_t *
uip_ds6_nbr_ipaddr_from_lladdr(const uip_lladdr_t *lladdr)
{
  LOG_ERR("uip_ds6_nbr_ipaddr_from_lladdr called\n");
  assert(false);
  return NULL;
}
/*---------------------------------------------------------------------------*/
const uip_lladdr_t *
uip_ds6_nbr_lladdr_from_ipaddr(const uip_ipaddr_t *ipaddr)
{
  uip_ds6_nbr_t *nbr = uip_ds6_nbr_lookup(ipaddr);
  return nbr ? uip_ds6_nbr_get_ll(nbr) : NULL;
}
/*---------------------------------------------------------------------------*/
void
uip_ds6_link_callback(int status, int numtx)
{
}
/*---------------------------------------------------------------------------*/
