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

#include "tiny-dice-l1.h"
#include "coap3/coap_internal.h"
#include <inttypes.h>

/* Log configuration */
#include "sys/log.h"
#define LOG_MODULE "TinyDICE"
#define LOG_LEVEL LOG_LEVEL_DBG

static uint8_t cert_chain_bytes[TINY_DICE_MAX_CERT_CHAIN_SIZE];
coap_bin_const_t tiny_dice_l1_cert_chain;
uint8_t tiny_dice_l1_public_key[ECC_CURVE_P_256_SIZE * 2];
uint8_t tiny_dice_l1_private_key[ECC_CURVE_P_256_SIZE];

/*---------------------------------------------------------------------------*/
void
tiny_dice_l1_set_cdi_l1(const uint8_t cdi_l1[static TINY_DICE_CDI_SIZE])
{
}
/*---------------------------------------------------------------------------*/
static void
pretty_print(const tiny_dice_cert_chain_t *const cert_chain, bool in_transit)
{
#if LOG_DBG_ENABLED
  for(size_t i = 0; i < cert_chain->length; i++) {
    const tiny_dice_cert_t *const cert = cert_chain->certs + i;

    if(!i && cert_chain->length >=2) {
      LOG_DBG("Cert_L0 (%s): ", in_transit ? "in transit" : "at rest");
    } else {
      LOG_DBG("Cert_L1 (%s): ", in_transit ? "in transit" : "at rest");
    }

    LOG_DBG_("{\n");
    if(cert->subject_size) {
      LOG_DBG("  subject: ");
      if(cert->subject_data) {
        LOG_DBG_BYTES(cert->subject_data, cert->subject_size);
      }
      LOG_DBG_(",\n");
    }

    if(cert->issuer_id) {
      LOG_DBG("  issuer: ");
      LOG_DBG_BYTES(cert->issuer_id, TINY_DICE_ISSUER_ID_SIZE);
      LOG_DBG_(",\n");
    } else if(!in_transit && (cert->issuer_hash == TINY_DICE_HASH_SHA256)) {
      LOG_DBG("  issuer: %i (SHA-256),\n", TINY_DICE_HASH_SHA256);
    }

    if(!in_transit && (cert->curve == TINY_DICE_CURVE_SECP256R1)) {
      LOG_DBG("  curve: %i (secp256r1),\n", TINY_DICE_CURVE_SECP256R1);
    }

    LOG_DBG("  reconstruction-data: ");
    LOG_DBG_BYTES(cert->reconstruction_data, sizeof(cert->reconstruction_data));
    LOG_DBG_(",\n");

    if(cert->tci_digest) {
      LOG_DBG("  tci: ");
      LOG_DBG_BYTES(cert->tci_digest, TINY_DICE_TCI_SIZE);
      LOG_DBG_("\n");
    } else if(cert->tci_version) {
      LOG_DBG("  tci: %" PRIu32 "\n", cert->tci_version);
    }
    LOG_DBG("}\n");
  }
#endif /* LOG_DBG_ENABLED */
}
/*---------------------------------------------------------------------------*/
bool
tiny_dice_l1_boot(const tiny_dice_cert_chain_t *const cert_chain)
{
  pretty_print(cert_chain, true);
  cbor_writer_state_t state;
  cbor_init_writer(&state, cert_chain_bytes, sizeof(cert_chain_bytes));
  tiny_dice_write_cert_chain(&state, cert_chain);
  tiny_dice_l1_cert_chain.s = cert_chain_bytes;
  tiny_dice_l1_cert_chain.length = cbor_end_writer(&state);
  return tiny_dice_l1_cert_chain.length != 0;
}
/*---------------------------------------------------------------------------*/

#endif /* TINY_DICE_L1_H_ */

/** @} */
