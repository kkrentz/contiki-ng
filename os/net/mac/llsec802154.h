/*
 * Copyright (c) 2013, Hasso-Plattner-Institut.
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
  * \addtogroup link-layer
  * @{
  *
  * \defgroup llsec802154 Link-layer security common functionality
  *
  * Macros related to 802.15.4 link-layer security.
  *
  * @{
  */

/**
 * \file
 *         Common functionality of 802.15.4-compliant llsec_drivers.
 * \author
 *         Konrad Krentz <konrad.krentz@gmail.com>
 */

#ifndef LLSEC802154_H_
#define LLSEC802154_H_

#include "net/mac/framer/frame802154.h"
#include "net/ipv6/uip.h"

#ifdef LLSEC802154_CONF_ENABLED
#define LLSEC802154_ENABLED            LLSEC802154_CONF_ENABLED
#else /* LLSEC802154_CONF_ENABLED */
#define LLSEC802154_ENABLED            0
#endif /* LLSEC802154_CONF_ENABLED */

#ifdef LLSEC802154_CONF_USES_EXPLICIT_KEYS
#define LLSEC802154_USES_EXPLICIT_KEYS LLSEC802154_CONF_USES_EXPLICIT_KEYS
#else /* LLSEC802154_CONF_USES_EXPLICIT_KEYS */
#define LLSEC802154_USES_EXPLICIT_KEYS LLSEC802154_ENABLED
#endif /* LLSEC802154_CONF_USES_EXPLICIT_KEYS */

#ifdef LLSEC802154_CONF_USES_AUX_HEADER
#define LLSEC802154_USES_AUX_HEADER    LLSEC802154_CONF_USES_AUX_HEADER
#else /* LLSEC802154_CONF_USES_AUX_HEADER */
#define LLSEC802154_USES_AUX_HEADER    LLSEC802154_ENABLED
#endif /* LLSEC802154_CONF_USES_AUX_HEADER */

#ifdef LLSEC802154_CONF_USES_FRAME_COUNTER
#define LLSEC802154_USES_FRAME_COUNTER LLSEC802154_CONF_USES_FRAME_COUNTER
#else
#define LLSEC802154_USES_FRAME_COUNTER LLSEC802154_ENABLED
#endif /* LLSEC802154_CONF_USES_FRAME_COUNTER */

#if UIP_BYTE_ORDER == UIP_LITTLE_ENDIAN
#define LLSEC802154_HTONS(n) (n)
#define LLSEC802154_HTONL(n) (n)
#else /* UIP_BYTE_ORDER == UIP_LITTLE_ENDIAN */
#define LLSEC802154_HTONS(n) (uint16_t)((((uint16_t) (n)) << 8) | (((uint16_t) (n)) >> 8))
#define LLSEC802154_HTONL(n) (((uint32_t)UIP_HTONS(n) << 16) | UIP_HTONS((uint32_t)(n) >> 16))
#endif /* UIP_BYTE_ORDER == UIP_LITTLE_ENDIAN */

#define LLSEC802154_MIC_LEN(sec_lvl)   (2 << (sec_lvl & 3))

#if LLSEC802154_USES_AUX_HEADER
#define LLSEC802154_PACKETBUF_MIC_LEN() LLSEC802154_MIC_LEN(packetbuf_attr(PACKETBUF_ATTR_SECURITY_LEVEL))
#else
#define LLSEC802154_PACKETBUF_MIC_LEN() 0
#endif

#endif /* LLSEC802154_H_ */

/** @} */
/** @} */
