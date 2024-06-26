/*
 * Copyright (c) 2008, Swedish Institute of Computer Science.
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
 *         Header file for the 6lowpan implementation
 *         (RFC4944 and draft-hui-6lowpan-hc-01)
 * \author Adam Dunkels <adam@sics.se>
 * \author Nicolas Tsiftes <nvt@sics.se>
 * \author Niclas Finne <nfi@sics.se>
 * \author Mathilde Durvy <mdurvy@cisco.com>
 * \author Julien Abeille <jabeille@cisco.com>
 */

/**
 * \addtogroup sicslowpan
 * @{
 */

#ifndef SICSLOWPAN_H_
#define SICSLOWPAN_H_

#include "net/ipv6/uip.h"
#include "net/mac/mac.h"

/**
 * \name General sicslowpan defines
 * @{
 */
/* Min and Max compressible UDP ports - HC06 */
#define SICSLOWPAN_UDP_4_BIT_PORT_MIN                     0xF0B0
#define SICSLOWPAN_UDP_4_BIT_PORT_MAX                     0xF0BF   /* F0B0 + 15 */
#define SICSLOWPAN_UDP_8_BIT_PORT_MIN                     0xF000
#define SICSLOWPAN_UDP_8_BIT_PORT_MAX                     0xF0FF   /* F000 + 255 */

/** @} */

/**
 * \name 6lowpan compressions
 * \note These are assumed to be in order - so that no compression is 0, then more and more
 *  compressed version follow. E.g. they can be used for comparing: if x > COMPRESSION_IPV6 ...
 * @{
 */
#define SICSLOWPAN_COMPRESSION_IPV6        0 /* No compression */
#define SICSLOWPAN_COMPRESSION_IPHC        1 /* RFC 6282 */
#define SICSLOWPAN_COMPRESSION_6LORH       2 /* RFC 8025 for paging dispatch,
              * draft-ietf-6lo-routin-dispatch-05 for 6LoRH. 6LoRH is not
              * implemented yet -- only support for paging dispatch. */
/** @} */

/**
 * \name 6lowpan dispatches
 * @{
 */
#define SICSLOWPAN_DISPATCH_IPV6                    0x41 /* 01000001 = 65 */
#define SICSLOWPAN_DISPATCH_HC1                     0x42 /* 01000010 = 66 */
#define SICSLOWPAN_DISPATCH_IPHC                    0x60 /* 011xxxxx = ... */
#define SICSLOWPAN_DISPATCH_IPHC_MASK               0xe0
#define SICSLOWPAN_DISPATCH_MESH                    0x80 /* 10xxxxxx */
#define SICSLOWPAN_DISPATCH_MESH_MASK               0xc0
#define SICSLOWPAN_DISPATCH_FRAG1                   0xc0 /* 11000xxx */
#define SICSLOWPAN_DISPATCH_FRAGN                   0xe0 /* 11100xxx */
#define SICSLOWPAN_DISPATCH_FRAG_MASK               0xf8
#define SICSLOWPAN_DISPATCH_PAGING                  0xf0 /* 1111xxxx */
#define SICSLOWPAN_DISPATCH_PAGING_MASK             0xf0
/** @} */

/** \name HC1 encoding
 * @{
 */
#define SICSLOWPAN_HC1_NH_UDP                       0x02
#define SICSLOWPAN_HC1_NH_TCP                       0x06
#define SICSLOWPAN_HC1_NH_ICMP6                     0x04
/** @} */

/** \name HC_UDP encoding (works together with HC1)
 * @{
 */
#define SICSLOWPAN_HC_UDP_ALL_C                     0xE0
/** @} */

/**
 * \name IPHC encoding
 * @{
 */
/*
 * Values of fields within the IPHC encoding first byte
 * (C stands for compressed and I for inline)
 */
#define SICSLOWPAN_IPHC_FL_C                        0x10
#define SICSLOWPAN_IPHC_TC_C                        0x08
#define SICSLOWPAN_IPHC_NH_C                        0x04
#define SICSLOWPAN_IPHC_TTL_1                       0x01
#define SICSLOWPAN_IPHC_TTL_64                      0x02
#define SICSLOWPAN_IPHC_TTL_255                     0x03
#define SICSLOWPAN_IPHC_TTL_I                       0x00


/* Values of fields within the IPHC encoding second byte */
#define SICSLOWPAN_IPHC_CID                         0x80

#define SICSLOWPAN_IPHC_SAC                         0x40
#define SICSLOWPAN_IPHC_SAM_00                      0x00
#define SICSLOWPAN_IPHC_SAM_01                      0x10
#define SICSLOWPAN_IPHC_SAM_10                      0x20
#define SICSLOWPAN_IPHC_SAM_11                      0x30

#define SICSLOWPAN_IPHC_SAM_BIT                     4

#define SICSLOWPAN_IPHC_M                           0x08
#define SICSLOWPAN_IPHC_DAC                         0x04
#define SICSLOWPAN_IPHC_DAM_00                      0x00
#define SICSLOWPAN_IPHC_DAM_01                      0x01
#define SICSLOWPAN_IPHC_DAM_10                      0x02
#define SICSLOWPAN_IPHC_DAM_11                      0x03

#define SICSLOWPAN_IPHC_DAM_BIT                     0

/* Link local context number */
#define SICSLOWPAN_IPHC_ADDR_CONTEXT_LL             0
/* 16-bit multicast addresses compression */
#define SICSLOWPAN_IPHC_MCAST_RANGE                 0xA0
/** @} */

/* NHC_EXT_HDR */
#define SICSLOWPAN_NHC_MASK                         0xF0
#define SICSLOWPAN_NHC_EXT_HDR                      0xE0
#define SICSLOWPAN_NHC_BIT                          0x01

/* The header values */
#define SICSLOWPAN_NHC_ETX_HDR_HBHO                 0x00
#define SICSLOWPAN_NHC_ETX_HDR_ROUTING              0x01
#define SICSLOWPAN_NHC_ETX_HDR_FRAG                 0x02
#define SICSLOWPAN_NHC_ETX_HDR_DESTO                0x03
#define SICSLOWPAN_NHC_ETX_HDR_MOH                  0x04
#define SICSLOWPAN_NHC_ETX_HDR_IPV6                 0x07

/* Mesh Addressing Type */
#ifdef SICSLOWPAN_CONF_INITIAL_MESH_HOPS
#define SICSLOWPAN_INITIAL_MESH_HOPS SICSLOWPAN_CONF_INITIAL_MESH_HOPS
#else /* SICSLOWPAN_CONF_INITIAL_MESH_HOPS */
#define SICSLOWPAN_INITIAL_MESH_HOPS 2
#endif /* SICSLOWPAN_CONF_INITIAL_MESH_HOPS */

#define SICSLOWPAN_MESH_VERY_FIRST                  (1 << 5)
#define SICSLOWPAN_MESH_FINAL_DESTINATION           (1 << 4)
#define SICSLOWPAN_MESH_HOPS_LEFT                   0x0F

/**
 * \name LOWPAN_UDP encoding (works together with IPHC)
 * @{
 */
#define SICSLOWPAN_NHC_UDP_MASK                     0xF8
#define SICSLOWPAN_NHC_UDP_ID                       0xF0
#define SICSLOWPAN_NHC_UDP_CHECKSUMC                0x04
#define SICSLOWPAN_NHC_UDP_CHECKSUMI                0x00
/* values for port compression, _with checksum_ ie bit 5 set to 0 */
#define SICSLOWPAN_NHC_UDP_CS_P_00  0xF0 /* all inline */
#define SICSLOWPAN_NHC_UDP_CS_P_01  0xF1 /* source 16bit inline, dest = 0xF0 + 8 bit inline */
#define SICSLOWPAN_NHC_UDP_CS_P_10  0xF2 /* source = 0xF0 + 8bit inline, dest = 16 bit inline */
#define SICSLOWPAN_NHC_UDP_CS_P_11  0xF3 /* source & dest = 0xF0B + 4bit inline */
/** @} */


/**
 * \name The 6lowpan "headers" length
 * @{
 */

#define SICSLOWPAN_IPV6_HDR_LEN                     1    /*one byte*/
#define SICSLOWPAN_HC1_HDR_LEN                      3
#define SICSLOWPAN_HC1_HC_UDP_HDR_LEN               7
#define SICSLOWPAN_FRAG1_HDR_LEN                    4
#define SICSLOWPAN_FRAGN_HDR_LEN                    5
/** @} */

/**
 * \brief An address context for IPHC address compression
 * each context can have upto 8 bytes
 */
struct sicslowpan_addr_context {
  uint8_t used; /* possibly use as prefix-length */
  uint8_t number;
  uint8_t prefix[8];
};

/**
 * \name Address compressibility test functions
 * @{
 */

/**
 * \brief check whether we can compress the IID in
 * address 'a' to 16 bits.
 * This is used for unicast addresses only, and is true
 * if the address is on the format \<PREFIX\>::0000:00ff:fe00:XXXX
 * NOTE: we currently assume 64-bits prefixes
 */
#define sicslowpan_is_iid_16_bit_compressable(a) \
  ((((a)->u16[4]) == 0) &&                       \
   (((a)->u8[10]) == 0)&&			    \
   (((a)->u8[11]) == 0xff)&&			    \
   (((a)->u8[12]) == 0xfe)&&			    \
   (((a)->u8[13]) == 0))

/**
 * \brief check whether the 9-bit group-id of the
 * compressed multicast address is known. It is true
 * if the 9-bit group is the all nodes or all routers
 * group.
 * \param a is typed uint8_t *
 */
#define sicslowpan_is_mcast_addr_decompressable(a) \
   (((*a & 0x01) == 0) &&                           \
    ((*(a + 1) == 0x01) || (*(a + 1) == 0x02)))

/**
 * \brief check whether the 112-bit group-id of the
 * multicast address is mappable to a 9-bit group-id
 * It is true if the group is the all nodes or all
 * routers group.
*/
#define sicslowpan_is_mcast_addr_compressable(a) \
  ((((a)->u16[1]) == 0) &&                       \
   (((a)->u16[2]) == 0) &&                       \
   (((a)->u16[3]) == 0) &&                       \
   (((a)->u16[4]) == 0) &&                       \
   (((a)->u16[5]) == 0) &&                       \
   (((a)->u16[6]) == 0) &&                       \
   (((a)->u8[14]) == 0) &&                       \
   ((((a)->u8[15]) == 1) || (((a)->u8[15]) == 2)))

/* FFXX::00XX:XXXX:XXXX */
#define sicslowpan_is_mcast_addr_compressable48(a) \
  ((((a)->u16[1]) == 0) &&                       \
   (((a)->u16[2]) == 0) &&                       \
   (((a)->u16[3]) == 0) &&                       \
   (((a)->u16[4]) == 0) &&                       \
   (((a)->u8[10]) == 0))

/* FFXX::00XX:XXXX */
#define sicslowpan_is_mcast_addr_compressable32(a) \
  ((((a)->u16[1]) == 0) &&                       \
   (((a)->u16[2]) == 0) &&                       \
   (((a)->u16[3]) == 0) &&                       \
   (((a)->u16[4]) == 0) &&                       \
   (((a)->u16[5]) == 0) &&                       \
   (((a)->u8[12]) == 0))

/* FF02::00XX */
#define sicslowpan_is_mcast_addr_compressable8(a) \
  ((((a)->u8[1]) == 2) &&                        \
   (((a)->u16[1]) == 0) &&                       \
   (((a)->u16[2]) == 0) &&                       \
   (((a)->u16[3]) == 0) &&                       \
   (((a)->u16[4]) == 0) &&                       \
   (((a)->u16[5]) == 0) &&                       \
   (((a)->u16[6]) == 0) &&                       \
   (((a)->u8[14]) == 0))

/** @} */

/**
 * The structure of a next header compressor.
 *
 * TODO: needs more parameters when compressing extension headers, etc.
 */
struct sicslowpan_nh_compressor {
  int (* is_compressable)(uint8_t next_header);

  /** compress next header (TCP/UDP, etc) - ptr points to next header to
      compress */
  int (* compress)(uint8_t *compressed, uint8_t *uncompressed_len);

  /** uncompress next header (TCP/UDP, etc) - ptr points to next header to
      uncompress */
  int (* uncompress)(uint8_t *compressed, uint8_t *lowpanbuf, uint8_t *uncompressed_len);

};

extern const struct network_driver sicslowpan_driver;

#endif /* SICSLOWPAN_H_ */
/** @} */
