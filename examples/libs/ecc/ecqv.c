/*
 * Copyright (c) 2024, Siemens AG.
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

#include "contiki.h"
#include "lib/ecc.h"
#include "lib/sha-256.h"

/* Log configuration */
#include "sys/log.h"
#define LOG_MODULE "ECQV"
#define LOG_LEVEL LOG_LEVEL_DBG

#define ECC_CURVE (&ecc_curve_p_256)
#define ECC_CURVE_SIZE (ECC_CURVE_P_256_SIZE)

struct cert_info {
  uint8_t reconstruction_data[ECC_CURVE_SIZE * 2];
  uint8_t hash[SHA_256_DIGEST_LENGTH];
};

PROCESS(ecqv_process, "ecqv_process");
AUTOSTART_PROCESSES(&ecqv_process);
static rtimer_clock_t t1, t2;

/*---------------------------------------------------------------------------*/
static uint64_t
get_milliseconds(void)
{
  uint64_t difference = t2 - t1;
  return (difference * 1000) / RTIMER_SECOND;
}
/*---------------------------------------------------------------------------*/
static int
encode_and_hash(const uint8_t *public_key_reconstruction_data,
                void *opaque,
                uint8_t *certificate_hash)
{
  struct cert_info *cert_info = (struct cert_info *)opaque;
  SHA_256.hash(public_key_reconstruction_data,
               sizeof(cert_info->reconstruction_data),
               certificate_hash);
  memcpy(cert_info->reconstruction_data,
         public_key_reconstruction_data,
         sizeof(cert_info->reconstruction_data));
  memcpy(cert_info->hash, certificate_hash, sizeof(cert_info->hash));
  return 1;
}
/*---------------------------------------------------------------------------*/
PROCESS_THREAD(ecqv_process, ev, data)
{
  int result;
  static uint8_t ca_public_key[ECC_CURVE_SIZE * 2];
  static uint8_t ca_private_key[ECC_CURVE_SIZE];
  static uint8_t proto_public_key[ECC_CURVE_SIZE * 2];
  static uint8_t proto_private_key[ECC_CURVE_SIZE];
  static struct cert_info cert_info;
  static uint8_t private_key_reconstruction_data[ECC_CURVE_SIZE];
  static uint8_t bobs_private_key[ECC_CURVE_SIZE];
  static uint8_t bobs_public_key[ECC_CURVE_SIZE * 2];
  static uint8_t bobs_reconstructed_public_key[ECC_CURVE_SIZE * 2];

  PROCESS_BEGIN();

  /* enable ECC driver */
  PROCESS_WAIT_UNTIL(process_mutex_try_lock(ecc_get_mutex()));
  if(ecc_enable(ECC_CURVE)) {
    LOG_ERR("enable failed\n");
    PROCESS_EXIT();
  }

  /* CA: generate public/private key pair*/
  PROCESS_PT_SPAWN(ecc_get_protothread(),
                   ecc_generate_key_pair(ca_public_key,
                                         ca_private_key,
                                         &result));
  if(result) {
    LOG_ERR("generate_key_pair failed\n");
    goto exit;
  }

  /* Bob: generate proto-public/private key pair*/
  PROCESS_PT_SPAWN(ecc_get_protothread(),
                   ecc_generate_key_pair(proto_public_key,
                                         proto_private_key,
                                         &result));
  if(result) {
    LOG_ERR("generate_key_pair failed\n");
    goto exit;
  }

  /* CA: validate proto-public key */
  t1 = RTIMER_NOW();
  PROCESS_PT_SPAWN(ecc_get_protothread(),
                   ecc_validate_public_key(proto_public_key, &result));
  if(result) {
    LOG_ERR("validate_public_key failed\n");
    goto exit;
  }

  /* CA: generate public key reconstruction data */
  PROCESS_PT_SPAWN(ecc_get_protothread(),
                   ecc_generate_ecqv_certificate(proto_public_key,
                                                 ca_private_key,
                                                 encode_and_hash,
                                                 &cert_info,
                                                 private_key_reconstruction_data,
                                                 &result));
  if(result) {
    LOG_ERR("generate_ecqv_certificate failed\n");
    goto exit;
  }

  /* Bob: generate actual public/private key pair */
  PROCESS_PT_SPAWN(ecc_get_protothread(),
                   ecc_generate_ecqv_key_pair(
                       proto_private_key,
                       cert_info.hash,
                       private_key_reconstruction_data,
                       bobs_public_key,
                       bobs_private_key,
                       &result));
  if(result) {
    LOG_ERR("generate_ecqv_key_pair failed\n");
    goto exit;
  }

  /* restore Bob's public key */
  t1 = RTIMER_NOW();
  PROCESS_PT_SPAWN(ecc_get_protothread(),
                   ecc_validate_public_key(cert_info.reconstruction_data,
                                           &result));
  if(result) {
    LOG_ERR("validate_public_key failed\n");
    goto exit;
  }
  PROCESS_PT_SPAWN(ecc_get_protothread(),
                   ecc_reconstruct_ecqv_public_key(
                       cert_info.hash,
                       cert_info.reconstruction_data,
                       ca_public_key,
                       bobs_reconstructed_public_key,
                       &result));
  if(result) {
    LOG_ERR("reconstruct_ecqv_public_key failed\n");
    goto exit;
  }
  t2 = RTIMER_NOW();
  LOG_INFO("reconstruction took %" PRIu64 "ms\n", get_milliseconds());

  if(!memcmp(bobs_public_key,
             bobs_reconstructed_public_key,
             sizeof(bobs_public_key))) {
    LOG_INFO("SUCCESS\n");
  } else {
    LOG_ERR("FAILURE\n");
  }

exit:
  ecc_disable();
  PROCESS_END();
}
/*---------------------------------------------------------------------------*/
