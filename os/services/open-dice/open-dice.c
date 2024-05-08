/*
 * Copyright (c) 2024, Siemens AG
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
 * \file
 *         Resembles the boot process of the Open Profile for DICE.
 * \author
 *         Konrad Krentz <konrad.krentz@gmail.com>
 */

#include "open-dice.h"
#include "coap3/coap_internal.h"
#include "lib/ecc.h"
#include "lib/hexconv.h"
#include "lib/sha-256.h"
#include "open-dice-asym-kdf.h"

/* Log configuration */
#include "sys/log.h"
#define LOG_MODULE "OpenDICE"
#ifdef ATTESTATION_BENCHMARK
#define LOG_LEVEL LOG_LEVEL_ERR
#else /* ATTESTATION_BENCHMARK */
#define LOG_LEVEL LOG_LEVEL_DBG
#endif /* ATTESTATION_BENCHMARK */

enum {
  LABEL_ISS = 1,
  LABEL_SUB = 2,
  LABEL_codeHash = -4670545,
  LABEL_codeDescriptor = -4670546,
  LABEL_configurationHash = -4670547,
  LABEL_configurationDescriptor = -4670548,
  LABEL_authorityHash = -4670549,
  LABEL_authorityDescriptor = -4670550,
  LABEL_mode = -4670551,
  LABEL_subjectPublicKey = -4670552,
  LABEL_keyUsage = -4670553,
  LABEL_profileName = -4670554,
};

#define COSE_KTY_LABEL (1)
#define COSE_KEY_TYPE_PUBLIC_KEY (1)
#define COSE_KEY_TYPE_PUBLIC_KEY_LABEL (-2)

static const uint8_t uds[OPEN_DICE_KEY_LEN];
static const uint8_t key_usage_bits[] = { 1 << 5 , 0 };
struct pt open_dice_pt;
static uint8_t cdi_attest[SHA_256_DIGEST_LENGTH];
static uint8_t uds_public[2 * ECC_CURVE_P_256_SIZE];
static uint8_t cdi_public[2 * ECC_CURVE_P_256_SIZE];
static char uds_id_hex[40];
static char cdi_id_hex[40];
#ifdef ATTESTATION_BENCHMARK
static rtimer_clock_t t1, t2;
extern uint32_t wait_sum;
#endif /* ATTESTATION_BENCHMARK */

/*---------------------------------------------------------------------------*/
static bool
compute_cdi_attest(void)
{
  static const uint8_t overall_hash[SHA_256_DIGEST_LENGTH];
  static const char cdi_attest_info[] = "CDI_Attest";
  static const size_t cdi_attest_info_len = sizeof(cdi_attest_info) - 1;

  return sha_256_hkdf(overall_hash, sizeof(overall_hash),
                      uds, sizeof(uds),
                      (const uint8_t *)cdi_attest_info, cdi_attest_info_len,
                      cdi_attest, sizeof(cdi_attest));
}
/*---------------------------------------------------------------------------*/
static bool
compute_id(const uint8_t public_key[static 2 * ECC_CURVE_P_256_SIZE],
           char id_hex[static 40])
{
  static const uint8_t id_salt[] = {
    0xDB, 0xDB, 0xAE, 0xBC, 0x80, 0x20, 0xDA, 0x9F,
    0xF0, 0xDD, 0x5A, 0x24, 0xC8, 0x3A, 0xA5, 0xA5,
    0x42, 0x86, 0xDF, 0xC2, 0x63, 0x03, 0x1E, 0x32,
    0x9B, 0x4D, 0xA1, 0x48, 0x43, 0x06, 0x59, 0xFE,
    0x62, 0xCD, 0xB5, 0xB7, 0xE1, 0xE0, 0x0F, 0xC6,
    0x80, 0x30, 0x67, 0x11, 0xEB, 0x44, 0x4A, 0xF7,
    0x72, 0x09, 0x35, 0x94, 0x96, 0xFC, 0xFF, 0x1D,
    0xB9, 0x52, 0x0B, 0xA5, 0x1C, 0x7B, 0x29, 0xEA
  };
  static const char id_info[] = "ID";
  static const size_t id_info_len = sizeof(id_info) - 1 /* truncate \0 */;
  uint8_t id[20];
  if(!sha_256_hkdf(id_salt, sizeof(id_salt),
                   public_key, 2 * ECC_CURVE_P_256_SIZE,
                   (const uint8_t *)id_info, id_info_len,
                   id, sizeof(id))) {
    return false;
  }
  hexconv_hexlify(id, sizeof(id), id_hex, 40);
  return true;
}
/*---------------------------------------------------------------------------*/
static void
write_exemplary_cdi_payload(cbor_writer_state_t *state)
{
  static const uint8_t code_hash[64];
  static const uint8_t configuration_descriptor[64];
  static const uint8_t authority_hash[64];
  static const uint8_t mode[1] = { 0x01 /* normal mode */ };

  cbor_open_data(state);
  cbor_open_map(state);

  /* issuer claim */
  cbor_write_unsigned(state, LABEL_ISS);
  cbor_write_text(state,
                  uds_id_hex,
                  sizeof(uds_id_hex));
  /* subject claim */
  cbor_write_unsigned(state, LABEL_SUB);
  cbor_write_text(state,
                  cdi_id_hex,
                  sizeof(cdi_id_hex));
  /* code hash claim */
  cbor_write_unsigned(state, LABEL_codeHash);
  cbor_write_data(state,
                  code_hash,
                  sizeof(code_hash));
  /* configuration descriptor claim */
  cbor_write_unsigned(state, LABEL_configurationDescriptor);
  cbor_write_data(state,
                  configuration_descriptor,
                  sizeof(configuration_descriptor));
  /* authorityHash claim */
  cbor_write_unsigned(state, LABEL_authorityHash);
  cbor_write_data(state,
                  authority_hash,
                  sizeof(authority_hash));
  /* mode claim */
  cbor_write_unsigned(state, LABEL_mode);
  cbor_write_data(state, mode, sizeof(mode));
  /* subjectPublicKey claim */
  cbor_write_unsigned(state, LABEL_subjectPublicKey);
  cbor_open_map(state); /* COSE_Key structure */
  cbor_write_unsigned(state, COSE_KTY_LABEL);
  cbor_write_unsigned(state, COSE_KEY_TYPE_PUBLIC_KEY);
  cbor_write_unsigned(state, COSE_KEY_TYPE_PUBLIC_KEY_LABEL);
  cbor_write_data(state, uds_public, sizeof(uds_public));
  cbor_close_map(state);
  /* keyUsage claim */
  cbor_write_unsigned(state, LABEL_keyUsage);
  cbor_write_data(state, key_usage_bits, sizeof(key_usage_bits));

  cbor_close_map(state);
  cbor_close_data(state);
}
/*---------------------------------------------------------------------------*/
PT_THREAD(open_dice_boot(int *const result))
{
  static uint8_t uds_private[ECC_CURVE_P_256_SIZE];
  static uint8_t cdi_private[ECC_CURVE_P_256_SIZE];
  uint8_t signature[2 * ECC_CURVE_P_256_SIZE];

  PT_BEGIN(&open_dice_pt);

  /* enable ECC */
  PT_WAIT_UNTIL(&open_dice_pt, process_mutex_try_lock(ecc_get_mutex()));
  if(ecc_enable(&ecc_curve_p_256)) {
    LOG_ERR("ecc_enable failed\n");
    *result = 1;
    PT_EXIT(&open_dice_pt);
  }

#ifdef ATTESTATION_BENCHMARK
static unsigned sample;
for(sample = 0; sample < 30; sample++) {
  wait_sum = 0;
  t1 = RTIMER_NOW();
#endif /* ATTESTATION_BENCHMARK */

  /* compute CDI_Attest */
  if(!compute_cdi_attest()) {
    LOG_ERR("ecc_enable failed\n");
    *result = 1;
    goto error;
  }

  /* deterministically generate UDS_Private and UDS_Public */
  if(!open_dice_asym_kdf_seed(uds)) {
    LOG_ERR("open_dice_asym_kdf_seed failed\n");
    *result = 1;
    goto error;
  }
  PT_SPAWN(&open_dice_pt,
           ecc_get_protothread(),
           ecc_generate_key_pair_deterministic(open_dice_asym_kdf_rand,
                                               uds_public,
                                               uds_private,
                                               result));
  if(*result) {
    LOG_ERR("ecc_generate_key_pair failed\n");
    *result = 1;
    goto error;
  }

  /* deterministically generate CDI_Private and CDI_Public */
  if(!open_dice_asym_kdf_seed(cdi_attest)) {
    LOG_ERR("open_dice_asym_kdf_seed failed\n");
    *result = 1;
    goto error;
  }
  PT_SPAWN(&open_dice_pt,
           ecc_get_protothread(),
           ecc_generate_key_pair_deterministic(open_dice_asym_kdf_rand,
                                               cdi_public,
                                               cdi_private,
                                               result));
  if(*result) {
    LOG_ERR("ecc_generate_key_pair failed\n");
    *result = 1;
    goto error;
  }

  /* derive UDS_ID and CDI_ID */
  if(!compute_id(uds_public, uds_id_hex)
     || !compute_id(cdi_public, cdi_id_hex)) {
    LOG_ERR("compute_id failed\n");
    *result = 1;
    goto error;
  }

  /*
   * To create the signature for the CDI certificate, we need to assemble:
   *
   * Sig_structure = [
   *   context : "Signature" / "Signature1" / "CounterSignature",
   *   body_protected : empty_or_serialized_map,
   *   ? sign_protected : empty_or_serialized_map, ; omitted in COSE_Sign1
   *   external_aad : bstr,
   *   payload : bstr
   * ]
   */
  {
    cbor_writer_state_t state;
    uint8_t sig_structure[512];
    uint8_t hash[SHA_256_DIGEST_LENGTH];

    cbor_init_writer(&state, sig_structure, sizeof(sig_structure));
    cbor_open_array(&state);
    /* context */
    cbor_write_text(&state, "Signature1", sizeof("Signature1") - 1);
    /* body_protected */
    cbor_write_data(&state, NULL, 0);
    /* external_aad */
    cbor_write_data(&state, NULL, 0);
    /* payload */
    write_exemplary_cdi_payload(&state);
    cbor_close_array(&state);
    size_t sig_structure_size = cbor_end_writer(&state);
    if(!sig_structure_size) {
      LOG_ERR("Error on LINE %i\n", __LINE__);
      *result = 1;
      PT_EXIT(&open_dice_pt);
    }
    if(!SHA_256.hash(sig_structure, sig_structure_size, hash)) {
      LOG_ERR("SHA_256.hash failed\n");
      *result = 1;
      goto error;
    }
    PT_SPAWN(&open_dice_pt,
             ecc_get_protothread(),
             ecc_sign(hash, uds_private, signature, result));
    if(*result) {
      LOG_ERR("ecc_sign failed\n");
      *result = 1;
      goto error;
    }
  }

  /*
   * Assemble CDI certificate. In OpenDICE, both UDS and CDI certificates are
   * untagged COSE_Sign1 messages, which have this format:
   *
   * COSE_Sign1 = [
   *   Headers,
   *   payload : bstr / nil,
   *   signature : bstr
   * ]
   *
   * Headers = (
   *   protected : empty_or_serialized_map,
   *   unprotected : header_map
   * )
   */
  {
    cbor_writer_state_t state;
    uint8_t cwt[512];

    cbor_init_writer(&state, cwt, sizeof(cwt));
    cbor_open_array(&state);
    /* protected: empty byte string */
    cbor_write_data(&state, NULL, 0);
    /* unprotected: empty map */
    cbor_open_map(&state);
    cbor_close_map(&state);
    /* payload */
    write_exemplary_cdi_payload(&state);
    /* signature */
    cbor_write_data(&state, signature, sizeof(signature));
    cbor_close_array(&state);
    size_t cwt_size = cbor_end_writer(&state);
    if(!cwt_size) {
      LOG_ERR("Error on LINE %i\n", __LINE__);
      *result = 1;
      goto error;
    }
    LOG_DBG("Size of CDI certificate: %zu bytes\n", cwt_size);
  }
#ifdef ATTESTATION_BENCHMARK
  t2 = RTIMER_NOW();
  printf("%s,open,%" RTIMER_PRI ",%" RTIMER_PRI "\n",
         WATCHDOG_CONF_ENABLE ? "yes" : "no",
         t2 - t1,
         wait_sum);
}
#endif /* ATTESTATION_BENCHMARK */

  *result = 0;
error:
  ecc_disable();

  PT_END(&open_dice_pt);
}
/*---------------------------------------------------------------------------*/
static void
write_exemplary_uds_payload(cbor_writer_state_t *state)
{
  static const char ca[8];

  cbor_open_data(state);
  cbor_open_map(state);

  /* issuer claim */
  cbor_write_unsigned(state, LABEL_ISS);
  cbor_write_text(state, ca, sizeof(ca));
  /* subject claim */
  cbor_write_unsigned(state, LABEL_SUB);
  cbor_write_text(state, cdi_id_hex, sizeof(cdi_id_hex));
  /* subjectPublicKey claim */
  cbor_write_unsigned(state, LABEL_subjectPublicKey);
  cbor_open_map(state); /* COSE_Key structure */
  cbor_write_unsigned(state, COSE_KTY_LABEL);
  cbor_write_unsigned(state, COSE_KEY_TYPE_PUBLIC_KEY);
  cbor_write_unsigned(state, COSE_KEY_TYPE_PUBLIC_KEY_LABEL);
  cbor_write_data(state, uds_public, sizeof(uds_public));
  cbor_close_map(state);
  /* keyUsage claim */
  cbor_write_unsigned(state, LABEL_keyUsage);
  cbor_write_data(state, key_usage_bits, sizeof(key_usage_bits));

  cbor_close_map(state);
  cbor_close_data(state);
}
/*---------------------------------------------------------------------------*/
PT_THREAD(open_dice_issue_uds_certificate(int *const result))
{
  cbor_writer_state_t state;
  uint8_t cwt[512];

  PT_BEGIN(&open_dice_pt);

  cbor_init_writer(&state, cwt, sizeof(cwt));
  cbor_open_array(&state);
  /* protected: empty byte string */
  cbor_write_data(&state, NULL, 0);
  /* unprotected: empty map */
  cbor_open_map(&state);
  cbor_close_map(&state);
  /* payload */
  write_exemplary_uds_payload(&state);
  /* signature */
  {
    static const uint8_t signature[2 * ECC_CURVE_P_256_SIZE];
    cbor_write_data(&state, signature, sizeof(signature));
  }
  cbor_close_array(&state);
  size_t cwt_size = cbor_end_writer(&state);
  if(!cwt_size) {
    LOG_ERR("Error on LINE %i\n", __LINE__);
    *result = 1;
    PT_EXIT(&open_dice_pt);
  }
  LOG_DBG("Size of UDS certificate: %zu bytes\n", cwt_size);
  *result = 0;

  PT_END(&open_dice_pt);
}
/*---------------------------------------------------------------------------*/
