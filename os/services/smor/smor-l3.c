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
 *         Routing driver of SMOR.
 * \author
 *         Konrad Krentz <konrad.krentz@gmail.com>
 */

#include "contiki-net.h"
#include "lib/assert.h"
#include "net/ipv6/sicslowpan.h"
#include "smor-db.h"
#include "smor-trickle.h"

/* Log configuration */
#include "sys/log.h"
#define LOG_MODULE "SMOR-L3"
#define LOG_LEVEL LOG_LEVEL_RPL

static const uip_ipaddr_t global_prefix
    = { .u16 = { UIP_HTONS(UIP_DS6_DEFAULT_PREFIX) } };
static const uip_lladdr_t border_router_lladdr =
#if LINKADDR_SIZE == 2
    { { 0x00 , 0x01 } };
#else /* LINKADDR_SIZE == 2 */
    { { 0x00 , 0x01 , 0x00 , 0x01 , 0x00 , 0x01 , 0x00 , 0x01 } };
#endif /* LINKADDR_SIZE == 2 */
static bool am_border_router;

/*---------------------------------------------------------------------------*/
static void
init(void)
{
  uip_ipaddr_t global_unicast_address;
  uip_ipaddr_copy(&global_unicast_address, &global_prefix);
  uip_ds6_set_addr_iid(&global_unicast_address, &uip_lladdr);
  if(!uip_ds6_addr_add(&global_unicast_address, 0, ADDR_MANUAL)) {
    LOG_ERR("uip_ds6_addr_add failed\n");
  }
  if(LOG_DBG_ENABLED) {
    LOG_DBG("IPv6 addresses: \n");
    for(size_t i = 0; i < UIP_DS6_ADDR_NB; i++) {
      uint8_t state = uip_ds6_if.addr_list[i].state;
      if(uip_ds6_if.addr_list[i].isused
          && (state == ADDR_TENTATIVE || state == ADDR_PREFERRED)) {
        LOG_DBG("   - ");
        LOG_DBG_6ADDR(&uip_ds6_if.addr_list[i].ipaddr);
        LOG_DBG_("\n");
      }
    }
  }
  smor_trickle_init();
}
/*---------------------------------------------------------------------------*/
static void
root_set_prefix(uip_ipaddr_t *prefix, uip_ipaddr_t *iid)
{
  /* TODO learn IPv6 network prefix from router advertisements */
  /* TODO distribute IPv6 network prefix as per 6LoWPAN-ND */
}
/*---------------------------------------------------------------------------*/
static int
root_start(void)
{
  am_border_router = true;
  return 0;
}
/*---------------------------------------------------------------------------*/
static int
node_is_root(void)
{
  return am_border_router;
}
/*---------------------------------------------------------------------------*/
static int
get_root_ipaddr(uip_ipaddr_t *ipaddr)
{
  uip_create_linklocal_prefix(ipaddr);
  uip_ds6_set_addr_iid(ipaddr, &border_router_lladdr);
  return 1;
}
/*---------------------------------------------------------------------------*/
static int
get_sr_node_ipaddr(uip_ipaddr_t *ipaddr, const uip_sr_node_t *node)
{
  if(!ipaddr || !node) {
    LOG_WARN("get_sr_node_ipaddr called with %p and %p\n", ipaddr, node);
    return 0;
  }
  uip_ipaddr_copy(ipaddr, &global_prefix);
  uip_ds6_set_addr_iid(ipaddr, &uip_lladdr);
  return 1;
}
/*---------------------------------------------------------------------------*/
static void
leave_network(void)
{
  am_border_router = false;
}
/*---------------------------------------------------------------------------*/
static int
node_has_joined(void)
{
  LOG_ERR("node_has_joined is specific to RPL\n");
  assert(false);
  return 1;
}
/*---------------------------------------------------------------------------*/
static int
node_is_reachable(void)
{
  return am_border_router || akes_nbr_count(AKES_NBR_PERMANENT);
}
/*---------------------------------------------------------------------------*/
static void
global_repair(const char *str)
{
  LOG_ERR("global_repair is specific to RPL\n");
  assert(false);
}
/*---------------------------------------------------------------------------*/
static void
local_repair(const char *str)
{
  LOG_ERR("local_repair is specific to RPL\n");
  assert(false);
}
/*---------------------------------------------------------------------------*/
static bool
ext_header_remove(void)
{
  return true; /* nothing to remove as we do not use IPv6 extension headers */
}
/*---------------------------------------------------------------------------*/
static int
ext_header_update(void)
{
  return 1; /* nothing to update as we do not use IPv6 extension headers */
}
/*---------------------------------------------------------------------------*/
static int
ext_header_hbh_update(uint8_t *ext_buf, int opt_offset)
{
  LOG_WARN("discarding packet with hop-by-hop extension header\n");
  return 0;
}
/*---------------------------------------------------------------------------*/
static int
ext_header_srh_update(void)
{
  LOG_WARN("discarding packet with source routing extension header\n");
  return 0;
}
/*---------------------------------------------------------------------------*/
/* we use this callback to override the next hop selection in tcpip.c */
static int
ext_header_srh_get_next_hop(uip_ipaddr_t *ipaddr)
{
  assert(!uip_is_addr_mcast(&UIP_IP_BUF->destipaddr));

  /* handle offlink destination */
  if((!uip_is_addr_linklocal(&UIP_IP_BUF->destipaddr)
      && !uip_ipaddr_prefixcmp(&global_prefix,
          &UIP_IP_BUF->destipaddr,
          UIP_DEFAULT_PREFIX_LEN))
      || ((LINKADDR_SIZE == 2) &&
          !sicslowpan_is_iid_16_bit_compressable(&UIP_IP_BUF->destipaddr))) {
    if(am_border_router) {
      /* pass packet to the cloud */
      return 0;
    }
    /* pass packet to border router */
    return get_root_ipaddr(ipaddr);
  }

  /* assume that the destination is a Layer 3 neighbor */
  /* TODO if am_border_router, limit destinations to those we know to exist */
  uip_ipaddr_copy(ipaddr, &UIP_IP_BUF->destipaddr);
  uip_create_linklocal_prefix(ipaddr);
  return 1;
}
/*---------------------------------------------------------------------------*/
static void
link_callback(const linkaddr_t *addr, int status, int numtx)
{
}
/*---------------------------------------------------------------------------*/
static void
neighbor_state_changed(uip_ds6_nbr_t *nbr)
{
}
/*---------------------------------------------------------------------------*/
static void
drop_route(uip_ds6_route_t *route)
{
  LOG_WARN("drop_route\n");
}
/*---------------------------------------------------------------------------*/
static uint8_t
is_in_leaf_mode(void)
{
  LOG_ERR("is_in_leaf_mode is specific to TSCH\n");
  assert(false);
  return 0;
}
/*---------------------------------------------------------------------------*/
const struct routing_driver smor_l3_routing_driver = {
  "SMOR",
  init,
  root_set_prefix,
  root_start,
  node_is_root,
  get_root_ipaddr,
  get_sr_node_ipaddr,
  leave_network,
  node_has_joined,
  node_is_reachable,
  global_repair,
  local_repair,
  ext_header_remove,
  ext_header_update,
  ext_header_hbh_update,
  ext_header_srh_update,
  ext_header_srh_get_next_hop,
  link_callback,
  neighbor_state_changed,
  drop_route,
  is_in_leaf_mode,
};
/*---------------------------------------------------------------------------*/
