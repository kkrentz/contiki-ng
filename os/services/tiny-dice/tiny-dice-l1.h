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
 *         Represents TinyDICE's Layer 1.
 * \author
 *         Konrad Krentz <konrad.krentz@gmail.com>
 */

#ifndef TINY_DICE_L1_H_
#define TINY_DICE_L1_H_

#include "lib/ecc-curve.h"
#include <coap3/coap.h>
#include <stdbool.h>
#include <stdint.h>

/**
 * \brief        Initializes CDI_L1.
 * \param cdi_l1 CDI_L1.
 */
void tiny_dice_l1_set_cdi_l1(const uint8_t cdi_l1[static TINY_DICE_CDI_SIZE]);

/**
 * \brief            Spells out the given TinyDICE certificate chain.
 * \param cert_chain The TinyDICE certificate chain.
 * \return           \c true on success and \c false otherwise.
 */
bool tiny_dice_l1_boot(const tiny_dice_cert_chain_t *cert_chain);

/**
 * The spelled out TinyDICE certificate chain.
 */
extern coap_bin_const_t tiny_dice_l1_cert_chain;

/**
 * The public portion of AKey_L0, i.e, the public key of Layer 1.
 */
extern uint8_t tiny_dice_l1_public_key[ECC_CURVE_P_256_SIZE * 2];

/**
 * The private portion of AKey_L0, i.e, the private key of Layer 1.
 */
extern uint8_t tiny_dice_l1_private_key[ECC_CURVE_P_256_SIZE];

#endif /* TINY_DICE_L1_H_ */

/** @} */
