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
 *         Resembles TinyDICE's layered boot process.
 * \author
 *         Konrad Krentz <konrad.krentz@gmail.com>
 */

#include "tiny-dice.h"
#include "coap3/coap_internal.h"
#include "lib/csprng.h"
#include "lib/ecc.h"
#include "lib/sha-256.h"
#include <stdbool.h>
#include <string.h>

/* Log configuration */
#include "sys/log.h"
#define LOG_MODULE "TinyDICE"
#define LOG_LEVEL LOG_LEVEL_DBG

static const uint8_t uds[TINY_DICE_UDS_SIZE];
static const uint8_t tci_l0[TINY_DICE_TCI_SIZE];
static const uint32_t tci_l0_version = 1;
static const uint8_t tci_l1[TINY_DICE_TCI_SIZE] = {
  0xe4, 0x40, 0x26, 0x24, 0x29, 0xfa, 0x0f, 0xa2,
  0x16, 0x0d, 0xe8, 0x78, 0xb6, 0x26, 0x7d, 0xb9,
  0xb1, 0x08, 0xfe, 0x56, 0xaa, 0x34, 0xaf, 0x3b,
  0xf0, 0x47, 0xdc, 0x14, 0xf9, 0x03, 0xe6, 0xad
};
static const uint32_t tci_l1_version = 1;
static const uint8_t ca_private_key[] = {
  0x0d, 0xd8, 0x82, 0x73, 0x55, 0xa6, 0x8e, 0x96,
  0x0b, 0x91, 0x5e, 0x92, 0x78, 0x52, 0x15, 0x35,
  0x1f, 0x9b, 0x8b, 0xea, 0x2e, 0x68, 0x97, 0x91,
  0x70, 0x4d, 0x74, 0x05, 0x9c, 0x50, 0x9e, 0x41
};
static const tiny_dice_tci_mapping_t l1_tci_mapping = {
  tci_l1, tci_l1_version
};
static const char *subject_text;
static const uint8_t *subject_data;
static size_t subject_size;
struct pt tiny_dice_pt;
static uint8_t cdi_l0[TINY_DICE_CDI_SIZE];
static struct deterministic_rng_info {
  uint32_t counter;
  uint8_t extra_info[TINY_DICE_TCI_SIZE];
} deterministic_rng_info;
static uint8_t cert_l0_hash[SHA_256_DIGEST_LENGTH];
static uint8_t private_key_reconstruction_data_l0[ECC_CURVE_P_256_SIZE];
static bool has_cert_l0;
static uint8_t cert_l0_bytes[TINY_DICE_MAX_CERT_SIZE];
static size_t cert_l0_size;
static uint8_t cert_chain_bytes[TINY_DICE_MAX_CERT_CHAIN_SIZE];
coap_bin_const_t tiny_dice_cert_chain;
uint8_t tiny_dice_public_key[2 * ECC_CURVE_P_256_SIZE];
uint8_t tiny_dice_private_key[ECC_CURVE_P_256_SIZE];

/*---------------------------------------------------------------------------*/
void
tiny_dice_set_subject_data(const uint8_t *s, size_t s_size)
{
  subject_data = s;
  subject_text = NULL;
  subject_size = s_size;
}
/*---------------------------------------------------------------------------*/
void
tiny_dice_set_subject_text(const char *s, size_t s_size)
{
  subject_data = NULL;
  subject_text = s;
  subject_size = s_size;
}
/*---------------------------------------------------------------------------*/
/* resemble how the bootloader generates CDI_L0 */
static void
init_cdi_l0(void)
{
  sha_256_hkdf_expand(uds, sizeof(uds),
                      tci_l0, sizeof(tci_l0),
                      cdi_l0, sizeof(cdi_l0));
}
/*---------------------------------------------------------------------------*/
static bool
deterministic_rng(uint8_t *result, size_t size)
{
  sha_256_hkdf_expand(cdi_l0, sizeof(cdi_l0),
                      (const uint8_t *)&deterministic_rng_info,
                      sizeof(deterministic_rng_info),
                      result, size);
  deterministic_rng_info.counter++;
  return true;
}
/*---------------------------------------------------------------------------*/
static int
encode_and_hash_cert_l0(const uint8_t *reconstruction_data,
                        void *opaque,
                        uint8_t *certificate_hash)
{
  tiny_dice_cert_t cert_l0;

  /* init Cert_L0 */
  tiny_dice_clear_cert(&cert_l0);
  cert_l0.subject_text = subject_text;
  cert_l0.subject_data = subject_data;
  cert_l0.subject_size = subject_size;
  ecc_compress_public_key(reconstruction_data, cert_l0.reconstruction_data);
  cert_l0.tci_version = tci_l0_version;

  /* write Cert_L0 */
  {
    cbor_writer_state_t state;
    cbor_init_writer(&state, cert_l0_bytes, sizeof(cert_l0_bytes));
    tiny_dice_write_cert(&state, &cert_l0);
    cert_l0_size = cbor_end_writer(&state);
    if(!cert_l0_size) {
      return 0;
    }
  }

  /* hash Cert_L0 */
  SHA_256.hash(cert_l0_bytes, cert_l0_size, certificate_hash);
  LOG_DBG("Cert_L0: %zu bytes\n", cert_l0_size);

  return 1;
}
/*---------------------------------------------------------------------------*/
PT_THREAD(tiny_dice_issue_cert_l0(int *const result))
{
  uint8_t proto_device_id_public_key[2 * ECC_CURVE_P_256_SIZE];

  PT_BEGIN(&tiny_dice_pt);

  init_cdi_l0();

  /* enable ECC */
  PT_WAIT_UNTIL(&tiny_dice_pt, process_mutex_try_lock(ecc_get_mutex()));
  if(ecc_enable(&ecc_curve_p_256)) {
    LOG_ERR("ecc_enable failed\n");
    *result = 1;
    PT_EXIT(&tiny_dice_pt);
  }

  /* deterministically generate proto-DeviceID */
  {
    uint8_t proto_device_id_private_key[ECC_CURVE_P_256_SIZE];

    deterministic_rng_info.counter = 0;
    ecc_set_csprng(deterministic_rng);
    PT_SPAWN(&tiny_dice_pt,
             ecc_get_protothread(),
             ecc_generate_key_pair(proto_device_id_public_key,
                                   proto_device_id_private_key,
                                   result));
    ecc_set_csprng(csprng_rand);
    if(*result) {
      LOG_ERR("ecc_generate_key_pair failed\n");
      goto error;
    }
  }

  /* issue Cert_L0 */
  PT_SPAWN(&tiny_dice_pt,
           ecc_get_protothread(),
           ecc_generate_ecqv_certificate(proto_device_id_public_key,
                                         ca_private_key,
                                         encode_and_hash_cert_l0,
                                         NULL,
                                         private_key_reconstruction_data_l0,
                                         result));
  if(*result) {
    LOG_ERR("ecc_generate_ecqv_certificate failed\n");
    goto error;
  }
  has_cert_l0 = true;

error:
  ecc_disable();

  PT_END(&tiny_dice_pt);
}
/*---------------------------------------------------------------------------*/
static int
encode_and_hash_cert_l1(const uint8_t *reconstruction_data,
                        void *opaque,
                        uint8_t *certificate_hash)
{
  tiny_dice_cert_t cert_l1;

  /* init Cert_L1 */
  tiny_dice_clear_cert(&cert_l1);
  cert_l1.subject_text = subject_text;
  cert_l1.subject_data = subject_data;
  cert_l1.subject_size = subject_size;
  if(has_cert_l0) {
    cert_l1.issuer_id = cert_l0_hash;
  }
  ecc_compress_public_key(reconstruction_data, cert_l1.reconstruction_data);
  cert_l1.tci_digest = tci_l1;

  /* begin certificate chain */
  cbor_writer_state_t state;
  cbor_init_writer(&state, cert_chain_bytes, sizeof(cert_chain_bytes));
  cbor_open_array(&state);

  if(has_cert_l0) {
    /* write Cert_L0 */
    cbor_write_object(&state, cert_l0_bytes, cert_l0_size);
  }

  /* write and hash Cert_L1 */
  {
    const uint8_t *const head = state.buffer;
    tiny_dice_write_cert(&state, &cert_l1);
    const uint8_t *const tail = state.buffer;
    if(!head || !tail) {
      return 0;
    }
    /* hash Cert_L1 */
    SHA_256.hash(head, tail - head, opaque);
    memcpy(certificate_hash, opaque, ECC_CURVE_P_256_SIZE);
    LOG_DBG("Cert_L1: %zu bytes\n", tail - head);
  }

  /* wrap up certificate chain */
  cbor_close_array(&state);
  tiny_dice_cert_chain.length = cbor_end_writer(&state);
  if(!tiny_dice_cert_chain.length) {
    return 0;
  }
  tiny_dice_cert_chain.s = cert_chain_bytes;
  return 1;
}
/*---------------------------------------------------------------------------*/
PT_THREAD(tiny_dice_boot(int *const result))
{
  static uint8_t proto_akey_l0_private_key[ECC_CURVE_P_256_SIZE];
  static uint8_t proto_device_id_private_key[ECC_CURVE_P_256_SIZE];
  static uint8_t cert_l1_hash[SHA_256_DIGEST_LENGTH];
  uint8_t proto_akey_l0_public_key[2 * ECC_CURVE_P_256_SIZE];
  uint8_t private_key_reconstruction_data_l1[ECC_CURVE_P_256_SIZE];

  PT_BEGIN(&tiny_dice_pt);

  if(!has_cert_l0) {
    init_cdi_l0();
  }

  /* enable ECC */
  PT_WAIT_UNTIL(&tiny_dice_pt, process_mutex_try_lock(ecc_get_mutex()));
  if(ecc_enable(&ecc_curve_p_256)) {
    LOG_ERR("ecc_enable failed\n");
    *result = 1;
    goto error;
  }

  /* deterministically generate (proto-)DeviceID */
  {
    uint8_t proto_device_id_public_key[2 * ECC_CURVE_P_256_SIZE];

    deterministic_rng_info.counter = 0;
    ecc_set_csprng(deterministic_rng);
    PT_SPAWN(&tiny_dice_pt,
             ecc_get_protothread(),
             ecc_generate_key_pair(proto_device_id_public_key,
                                   proto_device_id_private_key,
                                   result));
    if(*result) {
      LOG_ERR("ecc_generate_key_pair failed\n");
      goto error;
    }
  }

  /* deterministically generate proto-AKey_L0 */
  memcpy(deterministic_rng_info.extra_info, tci_l1, sizeof(tci_l1));
  PT_SPAWN(&tiny_dice_pt,
           ecc_get_protothread(),
           ecc_generate_key_pair(proto_akey_l0_public_key,
                                 proto_akey_l0_private_key,
                                 result));
  if(*result) {
    LOG_ERR("ecc_generate_key_pair failed\n");
    goto error;
  }

  /* switch back to normal CSPRNG */
  ecc_set_csprng(csprng_rand);

  if(has_cert_l0) {
    uint8_t device_id_public_key[2 * ECC_CURVE_P_256_SIZE];

    SHA_256.hash(cert_l0_bytes, cert_l0_size, cert_l0_hash);

    /* reconstruct DeviceID */
    PT_SPAWN(&tiny_dice_pt,
             ecc_get_protothread(),
             ecc_generate_ecqv_key_pair(proto_device_id_private_key,
                                        cert_l0_hash,
                                        private_key_reconstruction_data_l0,
                                        device_id_public_key,
                                        proto_device_id_private_key,
                                        result));
    if(*result) {
      LOG_ERR("ecc_generate_ecqv_key_pair failed\n");
      goto error;
    }
  }

  /* issue Cert_L1 */
  PT_SPAWN(&tiny_dice_pt,
           ecc_get_protothread(),
           ecc_generate_ecqv_certificate(proto_akey_l0_public_key,
                                         proto_device_id_private_key,
                                         encode_and_hash_cert_l1,
                                         cert_l1_hash,
                                         private_key_reconstruction_data_l1,
                                         result));
  if(*result) {
    LOG_ERR("ecc_generate_ecqv_certificate failed\n");
    goto error;
  }

  /* reconstruct AKey_L0 */
  PT_SPAWN(&tiny_dice_pt,
           ecc_get_protothread(),
           ecc_generate_ecqv_key_pair(proto_akey_l0_private_key,
                                      cert_l1_hash,
                                      private_key_reconstruction_data_l1,
                                      tiny_dice_public_key,
                                      tiny_dice_private_key,
                                      result));
  if(*result) {
    LOG_ERR("ecc_generate_ecqv_key_pair failed\n");
    goto error;
  }

  *result = 0;
error:
  ecc_disable();

  PT_END(&tiny_dice_pt);
}
/*---------------------------------------------------------------------------*/
static void
pretty_print(tiny_dice_cert_chain_t *cert_chain, bool in_transit)
{
#if LOG_DBG_ENABLED
  for(size_t i = 0; i < cert_chain->length; i++) {
    tiny_dice_cert_t *cert = cert_chain->certs + i;

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
tiny_dice_compress(void)
{
  tiny_dice_cert_chain_t cert_chain;
  {
    cbor_reader_state_t state;
    cbor_init_reader(&state,
                     tiny_dice_cert_chain.s,
                     tiny_dice_cert_chain.length);
    if(tiny_dice_decode_cert_chain(&state, &cert_chain) == SIZE_MAX) {
      return false;
    }
  }
  pretty_print(&cert_chain, false);
  tiny_dice_compress_cert_chain(&l1_tci_mapping, &cert_chain);
  assert(!cert_chain.certs[cert_chain.length - 1].tci_digest);
  pretty_print(&cert_chain, true);
  {
    cbor_writer_state_t state;
    cbor_init_writer(&state, cert_chain_bytes, sizeof(cert_chain_bytes));
    tiny_dice_write_cert_chain(&state, &cert_chain);
    tiny_dice_cert_chain.length = cbor_end_writer(&state);
    if(!tiny_dice_cert_chain.length) {
      return false;
    }
    tiny_dice_cert_chain.s = cert_chain_bytes;
  }
  return true;
}
/*---------------------------------------------------------------------------*/

/** @} */
