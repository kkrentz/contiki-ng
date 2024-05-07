/*
 * Copyright (c) 2021, Uppsala universitet.
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
 * \ingroup apps
 * \defgroup filtering A TEE-based remote denial-of-sleep defense
 * \brief Privacy-preserving en-route filtering of OSCORE-NG traffic.
 *
 * @{
 * \file
 *         Remote attestation and key sharing.
 * \author
 *         Konrad Krentz <konrad.krentz@gmail.com>
 */

#ifndef FILTERING_CLIENT_H_
#define FILTERING_CLIENT_H_

#include "contiki.h"
#include <coap3/coap.h>
#include <stdbool.h>
#include "net/mac/csl/csl-framer-potr.h"

typedef struct filtering_client_subscription_t {
  struct filtering_client_subscription_t *next;
  void (*const on_registered)(coap_context_t *context);
} filtering_client_subscription_t;

void filtering_client_start(void);
void filtering_client_subscribe(filtering_client_subscription_t *subscription);
void filtering_client_prolong(void);

#ifdef AGGREGATOR
struct pt *filtering_client_get_otp_retrieval_protothread(void);
PT_THREAD(filtering_client_retrieve_filtering_otp(bool *successful));
void filtering_client_get_filtering_otp(uint8_t dst[CSL_FRAMER_POTR_OTP_LEN]);
#else /* AGGREGATOR */
bool filtering_client_set_otp_key(void);
bool filtering_client_unset_otp_key(void);
#endif /* AGGREGATOR */

#endif /* FILTERING_CLIENT_H_ */

/** @} */
