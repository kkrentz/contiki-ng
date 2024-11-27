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
 *         Resembles TinyDICE's Layer 0.
 * \author
 *         Konrad Krentz <konrad.krentz@gmail.com>
 */

#ifndef TINY_DICE_L0_H_
#define TINY_DICE_L0_H_

#include "coap3/coap_internal.h"
#include "sys/pt.h"
#include <stdint.h>

/**
 * \brief        Initializes CDI_L0.
 * \param cdi_l0 CDI_L0.
 */
void tiny_dice_l0_set_cdi_l0(const uint8_t cdi_l0[static TINY_DICE_CDI_SIZE]);

/**
 * \brief            Generates Cert_L1, AKey_L0, and CDI_L1.
 * \param cert_chain Optionally a Cert_L0, and a partially initialized Cert_L1.
 * \param s_l0       NULLable private key reconstruction data of Cert_L0.
 * \param result     Returns \c 0 on success and an error code otherwise.
 */
PT_THREAD(tiny_dice_l0_boot(tiny_dice_cert_chain_t *cert_chain,
                            const uint8_t s_l0[ECC_CURVE_P_256_SIZE],
                            int *const result));

#endif /* TINY_DICE_L0_H_ */

/** @} */
