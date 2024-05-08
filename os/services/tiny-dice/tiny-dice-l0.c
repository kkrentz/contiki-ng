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

#include "tiny-dice-l0.h"
#include "lib/assert.h"
#include "lib/ecc.h"
#include "lib/ecc-curve.h"
#include "lib/sha-256.h"
#include "tiny-dice.h"
#include "tiny-dice-csprng.h"
#include "tiny-dice-l1.h"
#include "tiny-dice-rot.h"

/* Log configuration */
#include "sys/log.h"
#define LOG_MODULE "TinyDICE"
#ifdef ATTESTATION_BENCHMARK
#define LOG_LEVEL LOG_LEVEL_ERR
#else /* ATTESTATION_BENCHMARK */
#define LOG_LEVEL LOG_LEVEL_DBG
#endif /* ATTESTATION_BENCHMARK */

struct cert_l1 {
  tiny_dice_cert_t *cert;
  uint8_t hash[SHA_256_DIGEST_LENGTH];
};

#ifdef ATTESTATION_BENCHMARK
static rtimer_clock_t t1, t2;
extern uint32_t wait_sum;
#endif /* ATTESTATION_BENCHMARK */

/*---------------------------------------------------------------------------*/
void
tiny_dice_l0_set_cdi_l0(const uint8_t cdi_l0[static TINY_DICE_CDI_SIZE])
{
  tiny_dice_csprng_seed(cdi_l0);
}
/*---------------------------------------------------------------------------*/
static int
encode_and_hash_cert_l1(const uint8_t *reconstruction_data,
                        void *opaque,
                        uint8_t *certificate_hash)
{
  struct cert_l1 *cert_l1 = (struct cert_l1 *)opaque;

  /* set reconstruction data of Cert_L1 */
  ecc_compress_public_key(reconstruction_data,
                          cert_l1->cert->reconstruction_data);

  /* encode Cert_L1 */
  uint8_t cert_l1_bytes[TINY_DICE_MAX_CERT_SIZE];
  cbor_writer_state_t state;
  cbor_init_writer(&state, cert_l1_bytes, sizeof(cert_l1_bytes));
  tiny_dice_write_cert(&state, cert_l1->cert);
  size_t cert_l1_size = cbor_end_writer(&state);
  if(!cert_l1_size) {
    return 0;
  }

  /* hash Cert_L1 */
  SHA_256.hash(cert_l1_bytes, cert_l1_size, cert_l1->hash);
  memcpy(certificate_hash, cert_l1->hash, sizeof(cert_l1->hash));
  LOG_DBG("Cert_L1: %zu bytes\n", cert_l1_size);

  return 1;
}
/*---------------------------------------------------------------------------*/
PT_THREAD(tiny_dice_l0_boot(
    tiny_dice_cert_chain_t *const cert_chain,
    const uint8_t private_key_reconstruction_data_l0[ECC_CURVE_P_256_SIZE],
    int *const result))
{
  static uint8_t proto_device_id_private_key[ECC_CURVE_P_256_SIZE];
  static uint8_t proto_akey_l0_public_key[2 * ECC_CURVE_P_256_SIZE];
  static uint8_t proto_akey_l0_private_key[ECC_CURVE_P_256_SIZE];
  static uint8_t cert_l0_hash[SHA_256_DIGEST_LENGTH];
  static struct cert_l1 cert_l1;

  PT_BEGIN(&tiny_dice_pt);

  /* enable ECC */
  PT_WAIT_UNTIL(&tiny_dice_pt, process_mutex_try_lock(ecc_get_mutex()));
  if(ecc_enable(&ecc_curve_p_256)) {
    LOG_ERR("ecc_enable failed\n");
    *result = 1;
    goto error;
  }

#ifdef ATTESTATION_BENCHMARK
static unsigned sample;
for(sample = 0; sample < 30; sample++) {
  wait_sum = 0;
  tiny_dice_csprng_reset();
  t1 = RTIMER_NOW();
#endif /* ATTESTATION_BENCHMARK */

  /* deterministically generate (proto-)DeviceID */
  {
    uint8_t proto_device_id_public_key[2 * ECC_CURVE_P_256_SIZE];

    PT_SPAWN(&tiny_dice_pt,
             ecc_get_protothread(),
             ecc_generate_key_pair_deterministic(tiny_dice_csprng_rand,
                                                 proto_device_id_public_key,
                                                 proto_device_id_private_key,
                                                 result));
    if(*result) {
      LOG_ERR("ecc_generate_key_pair failed\n");
      goto error;
    }

#if LOG_DBG_ENABLED
    if(cert_chain->length == 1) {
      /* communication partners need to know this public key */
      printf("static const uint8_t iot_devices_public_key[PUBLIC_KEY_SIZE] = {");
      for (size_t i = 0; i < sizeof(proto_device_id_public_key); i++) {
        if (!(i % 8)) {
          printf("\n ");
        }
        printf(" 0x%02x,", proto_device_id_public_key[i]);
      }
      printf("\n};\n");
    }
#endif /* LOG_DBG_ENABLED */
  }

  /* deterministically generate proto-AKey_L0 */
  tiny_dice_csprng_salt(cert_chain->certs[cert_chain->length -1].tci_digest);
  PT_SPAWN(&tiny_dice_pt,
           ecc_get_protothread(),
           ecc_generate_key_pair_deterministic(tiny_dice_csprng_rand,
                                               proto_akey_l0_public_key,
                                               proto_akey_l0_private_key,
                                               result));
  if(*result) {
    LOG_ERR("ecc_generate_key_pair failed\n");
    goto error;
  }

  /* generate CDI_L1 */
  {
    uint8_t cdi_l1[TINY_DICE_CDI_SIZE];
    tiny_dice_csprng_rand(cdi_l1, sizeof(cdi_l1));
    tiny_dice_l1_set_cdi_l1(cdi_l1);
  }

  if(private_key_reconstruction_data_l0) {
    assert(cert_chain->length == 2);

    /* hash Cert_L0 and use that hash as issuer for Cert_L1 */
    {
      cbor_writer_state_t state;
      uint8_t cert_l0_bytes[TINY_DICE_MAX_CERT_SIZE];
      cbor_init_writer(&state, cert_l0_bytes, sizeof(cert_l0_bytes));
      tiny_dice_write_cert(&state, cert_chain->certs);
      size_t cert_l0_size = cbor_end_writer(&state);
      if(!cert_l0_size) {
        return 0;
      }
      SHA_256.hash(cert_l0_bytes, cert_l0_size, cert_l0_hash);
      cert_chain->certs[1].issuer_id = cert_l0_hash;
    }

    /* reconstruct DeviceID */
    {
      uint8_t device_id_public_key[2 * ECC_CURVE_P_256_SIZE];
      PT_SPAWN(&tiny_dice_pt,
               ecc_get_protothread(),
               ecc_generate_ecqv_key_pair(proto_device_id_private_key,
                                          cert_l0_hash,
                                          private_key_reconstruction_data_l0,
                                          device_id_public_key,
                                          proto_device_id_private_key,
                                          result));
    }
    if(*result) {
      LOG_ERR("ecc_generate_ecqv_key_pair failed\n");
      goto error;
    }
  } else {
    assert(cert_chain->length == 1);
  }

  /* issue Cert_L1 */
  {
    uint8_t private_key_reconstruction_data_l1[ECC_CURVE_P_256_SIZE];

    cert_l1.cert = &cert_chain->certs[cert_chain->length - 1];
    PT_SPAWN(&tiny_dice_pt,
             ecc_get_protothread(),
             ecc_generate_ecqv_certificate(proto_akey_l0_public_key,
                                           proto_device_id_private_key,
                                           encode_and_hash_cert_l1,
                                           &cert_l1,
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
                                        cert_l1.hash,
                                        private_key_reconstruction_data_l1,
                                        tiny_dice_l1_public_key,
                                        tiny_dice_l1_private_key,
                                        result));
  }
  if(*result) {
    LOG_ERR("ecc_generate_ecqv_key_pair failed\n");
    goto error;
  }

#ifdef ATTESTATION_BENCHMARK
  t2 = RTIMER_NOW();
  printf("%s,tiny-%s,%" RTIMER_PRI ",%" RTIMER_PRI "\n",
         WATCHDOG_CONF_ENABLE ? "yes" : "no",
         cert_chain->length == 2 ? "with" : "without",
         t2 - t1,
         wait_sum);
}
#endif /* ATTESTATION_BENCHMARK */

  *result = 0;
error:
  ecc_disable();

  PT_END(&tiny_dice_pt);
}
/*---------------------------------------------------------------------------*/

/** @} */
