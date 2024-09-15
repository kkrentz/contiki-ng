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

#ifndef PROJECT_CONF_H_
#define PROJECT_CONF_H_

/* Configure remote attestation protocol */
#define WITH_TRAP 1
#define WITH_IRAP 1 /* IRAP depends on WITH_TRAP */

/* DH-based remote attestation otherwise has stack overflows */
#define NBR_TABLE_CONF_MAX_NEIGHBORS 5

#define AGGREGATOR
#if CONTIKI_TARGET_COOJA
#define AGGREGATOR_OTP_WAIT_TIME 150 /* ms */
#else /* CONTIKI_TARGET_COOJA */
#define AGGREGATOR_OTP_WAIT_TIME 50 /* ms */
#endif /* CONTIKI_TARGET_COOJA */

/* Configure CoAP */
#include "coap_config.h"
#undef COAP_SERVER_SUPPORT
#define COAP_SERVER_SUPPORT 0
#undef COAP_PROXY_SUPPORT
#define COAP_PROXY_SUPPORT 0
#define LOG_CONF_LEVEL_COAP 3

/* Configure MAC layer */
#define LINKADDR_CONF_SIZE 2 /* use 2-byte MAC addresses */
#define CSL_CONF_CHANNELS { 26 } /* disable channel hopping */
#define CSL_CONF_COMPLIANT 0 /* enable denial-of-sleep defenses */
#include "net/mac/csl/csl-autoconf.inc" /* auto-configure the rest */
#define LOG_CONF_LEVEL_MAC 4 /* enable logging */

#endif /* PROJECT_CONF_H_ */
