/*
 * Copyright (c) 2025, Siemens AG.
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
 *         Resembles TinyDICE's layered boot process.
 * \author
 *         Konrad Krentz <konrad.krentz@gmail.com>
 */

#ifndef TINY_DICE_H_
#define TINY_DICE_H_

#include "contiki.h"
#include "lib/ecc.h"
#include <coap3/coap.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/**
 * \brief              Tells TinyDICE to use a CBOR byte string as subject.
 * \param subject_data Pointer to the CBOR byte string.
 * \param subject_size Length of the CBOR byte string.
 */
void tiny_dice_set_subject_data(const uint8_t *subject_data,
                                size_t subject_size);

/**
 * \brief              Tells TinyDICE to use a CBOR text string as subject.
 * \param subject_text Pointer to the CBOR text string.
 * \param subject_size Length of the CBOR text string.
 */
void tiny_dice_set_subject_text(const char *subject_text, size_t subject_size);

/**
 * \brief        Issues a Cert_L0 certificate using example values for the
 *               CA's private key, the subject's UDS, and the subject's TCI_L0.
 * \param result \c 0 on success and an error code otherwise.
 */
PT_THREAD(tiny_dice_issue_cert_l0(int *result));

/**
 * \brief        Resembles DICE's bootloader and TinyDICE's Layer 0 steps using
 *               example values for the subject's UDS, TCI_L0, and TCI_L1.
 * \param result \c 0 on success and an error code otherwise.
 */
PT_THREAD(tiny_dice_boot(int *result));

/**
 * \brief  Prepares the generated TinyDICE certificate chain for insertion in
 *         IRAP using an example mapping for TCI_L1.
 * \return \c true on success and \c false otherwise.
 */
bool tiny_dice_compress(void);

/**
 * The protothread of \c tiny_dice_issue_cert_l0 and \c tiny_dice_boot.
 */
extern struct pt tiny_dice_pt;

/**
 * The generated and potentially compressed TinyDICE certificate chain.
 */
extern coap_bin_const_t tiny_dice_cert_chain;

/**
 * The public portion of AKey_L0, i.e, the public key of Layer 1.
 */
extern uint8_t tiny_dice_public_key[ECC_CURVE_P_256_SIZE * 2];

/**
 * The private portion of AKey_L1, i.e, the private key of Layer 1.
 */
extern uint8_t tiny_dice_private_key[ECC_CURVE_P_256_SIZE];

#endif /* TINY_DICE_H_ */

/** @} */
