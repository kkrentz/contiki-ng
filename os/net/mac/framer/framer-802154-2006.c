/*
 * Copyright (c) 2025, Konrad-Felix Krentz
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
 */

/**
 * \file
 *         A stripped-down framer for IEEE 802.15.4-2006.
 * \author
 *         Konrad Krentz <konrad.krentz@gmail.com>
 */

#include "net/mac/anti-replay.h"
#include "net/mac/framer/frame802154.h"
#include "net/mac/llsec802154.h"
#include "net/packetbuf.h"
#include <stdbool.h>

#include "sys/log.h"
#define LOG_MODULE "framer-2006"
#define LOG_LEVEL LOG_LEVEL_FRAMER

/*---------------------------------------------------------------------------*/
#if LLSEC802154_USES_AUX_HEADER && LLSEC802154_USES_EXPLICIT_KEYS
static size_t
get_key_id_len(uint_fast8_t key_id_mode)
{
  switch(key_id_mode) {
  case FRAME802154_1_BYTE_KEY_ID_MODE:
    return 1;
  case FRAME802154_5_BYTE_KEY_ID_MODE:
    return 5;
  case FRAME802154_9_BYTE_KEY_ID_MODE:
    return 9;
  default:
    return 0;
  }
}
#endif /* LLSEC802154_USES_AUX_HEADER && LLSEC802154_USES_EXPLICIT_KEYS */
/*---------------------------------------------------------------------------*/
static int
hdr_length(void)
{
  return 2 /* Frame Control */
         + 1 /* Sequence Number */
         + 2 /* Destination PAN Identifier */
         /* Destination Address */
         + (packetbuf_holds_broadcast() ? 2 : LINKADDR_SIZE)
         + 0 /* Source PAN Identifier (always compressed) */
         + LINKADDR_SIZE /* Source Address */
#if LLSEC802154_USES_AUX_HEADER
         /* Auxiliary Security Header */
         + (packetbuf_attr(PACKETBUF_ATTR_SECURITY_LEVEL) ? 5 : 0)
#if LLSEC802154_USES_EXPLICIT_KEYS
         + get_key_id_len(packetbuf_attr(PACKETBUF_ATTR_KEY_ID_MODE))
#endif /* LLSEC802154_USES_EXPLICIT_KEYS */
#endif /* LLSEC802154_USES_AUX_HEADER */
         ;
}
/*---------------------------------------------------------------------------*/
static void
write_address(uint8_t *p, const linkaddr_t *const address)
{
  for(size_t i = 0; i < LINKADDR_SIZE; i++) {
    p[i] = address->u8[LINKADDR_SIZE - 1 - i];
  }
}
/*---------------------------------------------------------------------------*/
static int
create(void)
{
  if(!packetbuf_hdralloc(hdr_length())) {
    LOG_ERR("Out: packetbuf_hdralloc failed\n");
    return FRAMER_FAILED;
  }

  uint8_t *p = packetbuf_hdrptr();
  const uint8_t *const hdrptr = p;
  bool is_broadcast = packetbuf_holds_broadcast();
#if LLSEC802154_USES_AUX_HEADER
  uint_fast8_t security_level = packetbuf_attr(PACKETBUF_ATTR_SECURITY_LEVEL);
#endif /* LLSEC802154_USES_AUX_HEADER */

  /* Frame Type | Sec. Enabled | Frame Pending | Ack Request | PAN ID Compr. */
  *p++ = (packetbuf_attr(PACKETBUF_ATTR_FRAME_TYPE) & 7)
#if LLSEC802154_USES_AUX_HEADER
         | (security_level ? 1 << 3 : 0)
#endif /* LLSEC802154_USES_AUX_HEADER */
#if PACKETBUF_WITH_PENDING
         | (packetbuf_attr(PACKETBUF_ATTR_PENDING) ? 1 << 4 : 0)
#endif /* PACKETBUF_WITH_PENDING */
         | (packetbuf_attr(PACKETBUF_ATTR_MAC_ACK) && !is_broadcast
            ? 1 << 5
            : 0)
         | (1 << 6);

  /* Destination Addressing Mode | Frame Version | Source Addressing Mode */
  *p++ = ((is_broadcast || (LINKADDR_SIZE == 2))
          ? FRAME802154_SHORTADDRMODE << 2
          : FRAME802154_LONGADDRMODE << 2)
         | (FRAME802154_IEEE802154_2006 << 4)
         | (LINKADDR_SIZE == 2
            ? FRAME802154_SHORTADDRMODE << 6
            : FRAME802154_LONGADDRMODE << 6);

  /* Sequence Number */
  *p++ = packetbuf_attr(PACKETBUF_ATTR_MAC_SEQNO);

  /* Destination PAN ID */
  *p++ = IEEE802154_PANID & 0xFF;
  *p++ = IEEE802154_PANID >> 8;

  /* Destination address */
  if(is_broadcast) {
    *p++ = FRAME802154_BROADCASTADDR & 0xFF;
    *p++ = FRAME802154_BROADCASTADDR >> 8;
  } else {
    write_address(p, packetbuf_addr(PACKETBUF_ADDR_RECEIVER));
    p += LINKADDR_SIZE;
  }

  /* Source PAN ID (always compressed) */

  /* Source address */
  write_address(p, packetbuf_addr(PACKETBUF_ADDR_SENDER));
  p += LINKADDR_SIZE;

#if LLSEC802154_USES_AUX_HEADER
  /* Auxiliary Security Header */
  if(security_level) {
#if LLSEC802154_USES_EXPLICIT_KEYS
    uint_fast8_t key_id_mode = packetbuf_attr(PACKETBUF_ATTR_KEY_ID_MODE);
    if(key_id_mode > FRAME802154_1_BYTE_KEY_ID_MODE) {
      LOG_ERR("Out: Unsupported key identifier mode\n");
      return FRAMER_FAILED;
    }
#endif /* LLSEC802154_USES_EXPLICIT_KEYS */
    *p++ = security_level
#if LLSEC802154_USES_EXPLICIT_KEYS
           | (key_id_mode << 3)
#endif /* LLSEC802154_USES_EXPLICIT_KEYS */
           ;
    anti_replay_write_counter(p);
    p += 4;

#if LLSEC802154_USES_EXPLICIT_KEYS
    if(key_id_mode) {
      *p++ = packetbuf_attr(PACKETBUF_ATTR_KEY_INDEX);
    }
#endif /* LLSEC802154_USES_EXPLICIT_KEYS */
  }
#endif /* LLSEC802154_USES_AUX_HEADER */

  LOG_INFO("Out: %2X ", packetbuf_attr(PACKETBUF_ATTR_FRAME_TYPE));
  LOG_INFO_LLADDR(packetbuf_addr(PACKETBUF_ADDR_RECEIVER));
  LOG_INFO_(" %i %u (%u)\n",
            (int)(p - hdrptr),
            packetbuf_datalen(),
            packetbuf_totlen());

  return p - hdrptr;
}
/*---------------------------------------------------------------------------*/
static size_t
parse_address(uint8_t *p, uint_fast8_t addressing_mode, uint8_t type)
{
  linkaddr_t address;

  switch(addressing_mode) {
  case FRAME802154_SHORTADDRMODE:
    if((p[0] == (FRAME802154_BROADCASTADDR & 0xFF))
       && (p[1] == (FRAME802154_BROADCASTADDR >> 8))) {
      if(type == PACKETBUF_ADDR_SENDER) {
        LOG_ERR("In: Broadcast source address\n");
        return 0;
      }
      packetbuf_set_addr(type, &linkaddr_null);
    } else {
      if(LINKADDR_SIZE == 8) {
        LOG_ERR("In: Incompatible addressing mode\n");
        return 0;
      }
      address.u8[1] = p[0];
      address.u8[0] = p[1];
      packetbuf_set_addr(type, &address);
    }
    return 2;
  case FRAME802154_LONGADDRMODE:
    if(LINKADDR_SIZE == 2) {
      LOG_ERR("In: Incompatible addressing mode\n");
      return 0;
    }
    for(size_t i = 0; i < 8; i++) {
      address.u8[LINKADDR_SIZE - i - 1] = p[i];
    }
    packetbuf_set_addr(type, &address);
    return 8;
  default:
    LOG_ERR("In: Invalid addressing mode\n");
    return 0;
  }
}
/*---------------------------------------------------------------------------*/
static int
do_parse(void)
{
  uint8_t *p = packetbuf_hdrptr();
  const uint8_t *const hdrptr = p;

  /* Frame Type | Sec. Enabled | Frame Pending | Ack Request | PAN ID Compr. */
  packetbuf_set_attr(PACKETBUF_ATTR_FRAME_TYPE, *p & 7);
#if LLSEC802154_USES_AUX_HEADER
  bool security_enabled = (*p >> 3) & 1;
#endif /* LLSEC802154_USES_AUX_HEADER */
#if PACKETBUF_WITH_PENDING
  packetbuf_set_attr(PACKETBUF_ATTR_PENDING, (*p >> 4) & 1);
#endif /* PACKETBUF_WITH_PENDING */
  packetbuf_set_attr(PACKETBUF_ATTR_MAC_ACK, (*p >> 5) & 1);
  bool panid_compressed = (*p >> 6) & 1;
  p++;

  /* Dest. Addressing Mode | Frame Version | Source Addressing Mode */
  uint_fast8_t dst_addressing_mode = (*p >> 2) & 3;
  /* ignore Frame Version */
  uint_fast8_t src_addressing_mode = (*p >> 6) & 3;
  p++;

  /* Sequence Number */
  packetbuf_set_attr(PACKETBUF_ATTR_MAC_SEQNO, *p++);

  if(dst_addressing_mode) {
    /* Destination PAN ID */
    uint_fast16_t dst_pan_id = p[0] + (p[1] << 8);
    if((dst_pan_id != IEEE802154_PANID)
       && dst_pan_id != FRAME802154_BROADCASTPANDID) {
      LOG_WARN("In: For another PAN\n");
      return FRAMER_FAILED;
    }
    p += 2;

    /* Destination address */
    size_t dst_address_len = parse_address(p,
                                           dst_addressing_mode,
                                           PACKETBUF_ADDR_RECEIVER);
    if(!dst_address_len) {
      return FRAMER_FAILED;
    }
    p += dst_address_len;
  }

  if(src_addressing_mode) {
    /* Source PAN ID */
    if(!panid_compressed) {
      p += 2;
    }

    /* Source address */
    size_t src_address_len = parse_address(p,
                                           src_addressing_mode,
                                           PACKETBUF_ADDR_SENDER);
    if(!src_address_len) {
      return FRAMER_FAILED;
    }
    p += src_address_len;
  }

#if LLSEC802154_USES_AUX_HEADER
  if(security_enabled) {
    packetbuf_set_attr(PACKETBUF_ATTR_SECURITY_LEVEL, *p & 7);
#if LLSEC802154_USES_EXPLICIT_KEYS
    uint_fast8_t key_id_mode = (*p >> 3) & 3;
    if(key_id_mode > FRAME802154_1_BYTE_KEY_ID_MODE) {
      LOG_ERR("In: Unsupported key identifier mode\n");
      return FRAMER_FAILED;
    }
    packetbuf_set_attr(PACKETBUF_ATTR_KEY_ID_MODE, key_id_mode);
#endif /* LLSEC802154_USES_EXPLICIT_KEYS */
    p += 1;

    anti_replay_parse_counter(p);
    p += 4;
#if LLSEC802154_USES_EXPLICIT_KEYS
    if(key_id_mode) {
      packetbuf_set_attr(PACKETBUF_ATTR_KEY_INDEX, *p++);
    }
#endif /* LLSEC802154_USES_EXPLICIT_KEYS */
  }
#endif /* LLSEC802154_USES_AUX_HEADER */

  return p - hdrptr;
}
/*---------------------------------------------------------------------------*/
static int
parse(void)
{
  int header_len = do_parse();
  if(header_len == FRAMER_FAILED) {
    return FRAMER_FAILED;
  }
  if(!packetbuf_hdrreduce(header_len)) {
    LOG_ERR("In: packetbuf_hdrreduce failed\n");
    return FRAMER_FAILED;
  }

  LOG_INFO("In: %2X ", packetbuf_attr(PACKETBUF_ATTR_FRAME_TYPE));
  LOG_INFO_LLADDR(packetbuf_addr(PACKETBUF_ADDR_SENDER));
  LOG_INFO_(" ");
  LOG_INFO_LLADDR(packetbuf_addr(PACKETBUF_ADDR_RECEIVER));
  LOG_INFO_(" %i %u (%u)\n",
            header_len,
            packetbuf_datalen(),
            packetbuf_totlen());

  return header_len;
}
/*---------------------------------------------------------------------------*/
const struct framer framer_802154_2006 = {
  hdr_length,
  create,
  parse
};
/*---------------------------------------------------------------------------*/
