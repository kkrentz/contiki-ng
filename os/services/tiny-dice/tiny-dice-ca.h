/*
 * Copyright (c) 2025, Siemens AG
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
 * \addtogroup crypto
 * @{
 *
 * \file
 *         Issuance of TinyDICE Cert_L0 certificates.
 * \author
 *         Konrad Krentz <konrad.krentz@gmail.com>
 */

#ifndef TINY_DICE_CA_H_
#define TINY_DICE_CA_H_

#include "coap3/coap_internal.h"
#include "lib/ecc-curve.h"
#include "lib/sha-256.h"
#include "sys/pt.h"
#include <stdint.h>

struct tiny_dice_ca_context {
  struct pt pt;
  tiny_dice_cert_t *cert_l0; /**< Partially initialized Cert_L0. */
  uint8_t reconstruction_data[ECC_CURVE_P_256_SIZE * 2];
  uint8_t hash[SHA_256_DIGEST_LENGTH];
};

/**
 * \brief         Issues a Cert_L0 and private key reconstruction data.
 * \param ctx     Context with the protothread to use and a partially
 *                initialized Cert_L0.
 * \param s_l0    Buffer to store the private key reconstruction data.
 * \param result  Returns \c 0 on success and an error code otherwise.
 */
PT_THREAD(tiny_dice_ca_request(struct tiny_dice_ca_context *ctx,
                               uint8_t s_l0[static ECC_CURVE_P_256_SIZE],
                               int *result));

#endif /* TINY_DICE_CA_H_ */

/** @} */
