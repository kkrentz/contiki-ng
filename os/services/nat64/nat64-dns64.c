/*
 * Copyright (c) 2026, RISE Research Institutes of Sweden AB.
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
 * \addtogroup nat64
 * @{
 *
 * \file
 *         NAT64 DNS64 translation -- rewrites DNS queries (AAAA->A)
 *         and responses (A->AAAA with NAT64 prefix) inline.
 *
 *         The translator handles compressed DNS names (RFC 1035
 *         §4.1.4), grows A records to AAAA records via the NAT64
 *         prefix synthesis from `ip64_addr_4to6`, and truncates the
 *         authority and additional sections after expansion since
 *         their offsets become invalid (and constrained resolvers
 *         do not consume them).
 * \author
 *         Nicolas Tsiftes <nicolas.tsiftes@ri.se>
 */

#include "nat64-dns64.h"
#include "net/ipv6/uip.h"
#include "ipv6/ip64-addr.h"

#include <string.h>

/* Log configuration */
#include "sys/log.h"
#define LOG_MODULE "NAT64"
#define LOG_LEVEL LOG_LEVEL_INFO

/* DNS record types per RFC 1035 / RFC 3596. */
#define DNS_TYPE_A      1
#define DNS_TYPE_AAAA  28
#define DNS_CLASS_IN    1

/* Offsets within the fixed-size DNS header (RFC 1035, Section 4.1.1). */
#define DNS_HDR_SIZE       12
#define DNS_HDR_ID          0
#define DNS_HDR_QDCOUNT     4
#define DNS_HDR_ANCOUNT     6
#define DNS_HDR_NSCOUNT     8
#define DNS_HDR_ARCOUNT    10

/* Offsets within the question tail (after the QNAME labels). */
#define DNS_QTAIL_QTYPE     0
#define DNS_QTAIL_QCLASS    2
#define DNS_QTAIL_SIZE      4

/* Read a big-endian uint16 from a byte buffer. */
#define RD16(p) (((uint16_t)(p)[0] << 8) | (p)[1])
/* Write a big-endian uint16 into a byte buffer. */
#define WR16(p, v) do { (p)[0] = (uint8_t)((v) >> 8); \
                        (p)[1] = (uint8_t)(v); } while(0)
/*---------------------------------------------------------------------------*/
/*
 * Skip over a DNS name in a packet (handling label sequences and
 * compressed pointers per RFC 1035 Section 4.1.4).
 * Returns a pointer past the name, or NULL on error.
 */
static const uint8_t *
skip_dns_name(const uint8_t *p, const uint8_t *end)
{
  while(p < end) {
    uint8_t len = *p;
    if(len == 0) {
      /* Root label terminates the name. */
      return p + 1;
    }
    if((len & 0xc0) == 0xc0) {
      /* Compressed pointer: two bytes total. */
      return (p + 2 <= end) ? p + 2 : NULL;
    }
    /* Regular label: skip length byte + label bytes. */
    p += 1 + len;
  }
  return NULL;
}
/*---------------------------------------------------------------------------*/
void
nat64_dns64_6to4(uint8_t *data, uint16_t len)
{
  uint16_t qdcount;
  uint8_t *p;
  const uint8_t *end;

  if(len < DNS_HDR_SIZE) {
    return;
  }

  qdcount = RD16(&data[DNS_HDR_QDCOUNT]);
  p = data + DNS_HDR_SIZE;
  end = data + len;

  LOG_DBG("DNS64 6to4: id=0x%04x, %u questions\n",
          RD16(&data[DNS_HDR_ID]), qdcount);

  /* Walk each question and change AAAA queries to A. */
  for(uint16_t i = 0; i < qdcount; i++) {
    const uint8_t *after_name = skip_dns_name(p, end);
    if(after_name == NULL || after_name + DNS_QTAIL_SIZE > end) {
      LOG_WARN("DNS64 6to4: malformed question section\n");
      return;
    }
    /* Point to the fixed question-tail (QTYPE, QCLASS). */
    uint8_t *qtail = (uint8_t *)after_name;
    if(RD16(&qtail[DNS_QTAIL_QTYPE]) == DNS_TYPE_AAAA &&
       RD16(&qtail[DNS_QTAIL_QCLASS]) == DNS_CLASS_IN) {
      WR16(&qtail[DNS_QTAIL_QTYPE], DNS_TYPE_A);
    }
    p = qtail + DNS_QTAIL_SIZE;
  }
}
/*---------------------------------------------------------------------------*/
uint16_t
nat64_dns64_4to6(const uint8_t *ipv4data, uint16_t ipv4len,
                 uint8_t *ipv6data, uint16_t ipv6len,
                 uint16_t ipv6bufsiz)
{
  uint16_t qdcount, ancount;
  const uint8_t *src;
  uint8_t *dst;
  const uint8_t *src_end;
  const uint8_t *dst_end = ipv6data + ipv6bufsiz;

  if(ipv4len < DNS_HDR_SIZE) {
    return ipv6len;
  }

  qdcount = RD16(&ipv4data[DNS_HDR_QDCOUNT]);
  ancount = RD16(&ipv4data[DNS_HDR_ANCOUNT]);
  src = ipv4data + DNS_HDR_SIZE;
  dst = ipv6data + DNS_HDR_SIZE;
  src_end = ipv4data + ipv4len;

  LOG_DBG("DNS64 4to6: id=0x%04x, %u answers\n",
          RD16(&ipv4data[DNS_HDR_ID]), ancount);

  /* Skip past the question section in both src and dst buffers.
   * Also patch QTYPE from A back to AAAA in the output. */
  for(uint16_t i = 0; i < qdcount; i++) {
    const uint8_t *after_name = skip_dns_name(src, src_end);
    if(after_name == NULL || after_name + DNS_QTAIL_SIZE > src_end) {
      return ipv6len;
    }
    /* Advance dst by the same amount (data was already copied by caller). */
    dst = ipv6data + (after_name - ipv4data);
    if(RD16(&dst[DNS_QTAIL_QTYPE]) == DNS_TYPE_A &&
       RD16(&dst[DNS_QTAIL_QCLASS]) == DNS_CLASS_IN) {
      WR16(&dst[DNS_QTAIL_QTYPE], DNS_TYPE_AAAA);
    }
    src = after_name + DNS_QTAIL_SIZE;
    dst = ipv6data + (src - ipv4data);
  }

  /* Now process each answer RR.  A (4-byte RDATA) records are expanded
   * to AAAA (16 bytes), shifting all subsequent data by +12 per record.
   * After the answer section we truncate authority and additional
   * sections rather than attempting to relocate them — their data would
   * be at wrong offsets after expansion, and IoT resolvers do not need
   * them. */
  uint16_t emitted_ancount = 0;
  /* Marks the start of the current answer's output bytes.  On a
   * mid-RR truncate, dst is rewound to this point so the message
   * doesn't end on a partially-written record. */
  uint8_t *rr_start = dst;
  for(uint16_t i = 0; i < ancount; i++) {
    rr_start = dst;

    /* Copy/skip the name in the answer. */
    const uint8_t *name_end = skip_dns_name(src, src_end);
    if(name_end == NULL) {
      goto truncate;
    }
    size_t name_len = name_end - src;
    if(dst + name_len > dst_end) {
      LOG_WARN("DNS64 4to6: output buffer full at name copy\n");
      goto truncate;
    }
    memcpy(dst, src, name_len);
    src += name_len;
    dst += name_len;

    /* We need at least 10 bytes for TYPE(2)+CLASS(2)+TTL(4)+RDLENGTH(2). */
    if(src + 10 > src_end) {
      goto truncate;
    }

    uint16_t rr_type = RD16(&src[0]);
    uint16_t rdlength = RD16(&src[8]);

    if(rr_type == DNS_TYPE_A && rdlength == 4 && src + 10 + 4 <= src_end) {
      /* Rewrite A -> AAAA: change type and expand the 4-byte address
       * to a 16-byte NAT64-prefixed IPv6 address (10 + 16 = 26 bytes). */
      if(dst + 10 + 16 > dst_end) {
        LOG_WARN("DNS64 4to6: output buffer full\n");
        goto truncate;
      }
      WR16(&dst[0], DNS_TYPE_AAAA);       /* TYPE = AAAA */
      memcpy(&dst[2], &src[2], 2 + 4);    /* CLASS + TTL unchanged */
      WR16(&dst[8], 16);                   /* RDLENGTH = 16 */
      dst += 10;
      src += 10;

      /* Synthesize IPv6 address from the IPv4 address. */
      uip_ip4addr_t a4;
      memcpy(&a4, src, 4);
      ip64_addr_4to6(&a4, (uip_ip6addr_t *)dst);

      src += 4;
      dst += 16;
    } else {
      /* Non-A or unexpected RDLENGTH: copy verbatim. */
      size_t rr_total = 10 + rdlength;
      if(src + rr_total > src_end) {
        goto truncate;
      }
      if(dst + rr_total > dst_end) {
        LOG_WARN("DNS64 4to6: output buffer full\n");
        goto truncate;
      }
      memcpy(dst, src, rr_total);
      src += rr_total;
      dst += rr_total;
    }
    emitted_ancount++;
  }
  /* All answers emitted successfully: nothing to rewind. */
  rr_start = dst;

truncate:
  /* Rewind any partially-written final RR so the message ends on a
   * complete record, then publish the count actually emitted. */
  dst = rr_start;
  WR16(&ipv6data[DNS_HDR_ANCOUNT], emitted_ancount);
  /* Drop authority and additional sections — they would be at wrong
   * offsets after answer expansion, and IoT resolvers don't need them. */
  WR16(&ipv6data[DNS_HDR_NSCOUNT], 0);
  WR16(&ipv6data[DNS_HDR_ARCOUNT], 0);
  return (uint16_t)(dst - ipv6data);
}
/*---------------------------------------------------------------------------*/
/** @} */
