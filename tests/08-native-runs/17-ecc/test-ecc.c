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
 * 3. Neither the name of the copyright holder nor the names of its
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDER AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
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
#include "unit-test.h"
#include "lib/ecc.h"
#include "lib/sha-256.h"
#include <stdio.h>
#include <string.h>

#define ECC_CURVE (&ecc_curve_p_256)
#define ECC_CURVE_SIZE (ECC_CURVE_P_256_SIZE)

struct cert_info {
  uint8_t reconstruction_data[ECC_CURVE_SIZE * 2];
  uint8_t hash[SHA_256_DIGEST_LENGTH];
};

PROCESS(test_process, "test");
AUTOSTART_PROCESSES(&test_process);

/*---------------------------------------------------------------------------*/
UNIT_TEST_REGISTER(ecc_compress, "Compress and decompress a public key");
UNIT_TEST(ecc_compress)
{
  int result;
  static uint8_t public_key[ECC_CURVE_SIZE * 2];
  static uint8_t private_key[ECC_CURVE_SIZE];
  static uint8_t compressed_public_key[ECC_CURVE_SIZE + 1];
  uint8_t uncompressed_public_key[ECC_CURVE_SIZE * 2];

  UNIT_TEST_BEGIN();

  /* enable ECC driver */
  PT_WAIT_UNTIL(&unit_test_pt, process_mutex_try_lock(ECC.get_mutex()));
  UNIT_TEST_ASSERT(!ECC.enable(ECC_CURVE));

  /* generate key pair */
  PT_SPAWN(&unit_test_pt,
           ECC.get_protothread(),
           ECC.generate_key_pair(public_key, private_key, &result));
  if(result) {
    UNIT_TEST_FAIL();
  }

  /* compress & decompress */
  ECC.compress_public_key(public_key, compressed_public_key);
  PT_SPAWN(&unit_test_pt,
           ECC.get_protothread(),
           ECC.decompress_public_key(compressed_public_key,
                                     uncompressed_public_key,
                                     &result));
  if(result) {
    UNIT_TEST_FAIL();
  }

  /* disable ECC driver */
  ECC.disable();

  /* check */
  UNIT_TEST_ASSERT(
    !memcmp(public_key, uncompressed_public_key, sizeof(public_key)));

  UNIT_TEST_END();
}
/*---------------------------------------------------------------------------*/
UNIT_TEST_REGISTER(ecc_ecdh, "ECDH");
UNIT_TEST(ecc_ecdh)
{
  int result;
  static uint8_t public_key_a[ECC_CURVE_SIZE * 2];
  static uint8_t private_key_a[ECC_CURVE_SIZE];
  static uint8_t public_key_b[ECC_CURVE_SIZE * 2];
  static uint8_t private_key_b[ECC_CURVE_SIZE];
  static uint8_t k_a[ECC_CURVE_SIZE];
  static uint8_t k_b[ECC_CURVE_SIZE];

  UNIT_TEST_BEGIN();

  /* enable ECC driver */
  PT_WAIT_UNTIL(&unit_test_pt, process_mutex_try_lock(ECC.get_mutex()));
  UNIT_TEST_ASSERT(!ECC.enable(ECC_CURVE));

  /* generate key pairs */
  PT_SPAWN(&unit_test_pt,
           ECC.get_protothread(),
           ECC.generate_key_pair(public_key_a, private_key_a, &result));
  if(result) {
    UNIT_TEST_FAIL();
  }
  PT_SPAWN(&unit_test_pt,
           ECC.get_protothread(),
           ECC.generate_key_pair(public_key_b, private_key_b, &result));
  if(result) {
    UNIT_TEST_FAIL();
  }

  /* validate public keys */
  PT_SPAWN(&unit_test_pt,
           ECC.get_protothread(),
           ECC.validate_public_key(public_key_a, &result));
  if(result) {
    UNIT_TEST_FAIL();
  }
  PT_SPAWN(&unit_test_pt,
           ECC.get_protothread(),
           ECC.validate_public_key(public_key_b, &result));
  if(result) {
    UNIT_TEST_FAIL();
  }

  /* run ECDH */
  PT_SPAWN(&unit_test_pt,
           ECC.get_protothread(),
           ECC.generate_shared_secret(public_key_b,
                                      private_key_a,
                                      k_a,
                                      &result));
  if(result) {
    UNIT_TEST_FAIL();
  }
  PT_SPAWN(&unit_test_pt,
           ECC.get_protothread(),
           ECC.generate_shared_secret(public_key_a,
                                      private_key_b,
                                      k_b,
                                      &result));
  if(result) {
    UNIT_TEST_FAIL();
  }

  /* disable ECC driver */
  ECC.disable();

  /* check */
  UNIT_TEST_ASSERT(!memcmp(k_a, k_b, ECC_CURVE_SIZE));

  UNIT_TEST_END();
}
/*---------------------------------------------------------------------------*/
UNIT_TEST_REGISTER(ecc_ecdsa, "ECDSA");
UNIT_TEST(ecc_ecdsa)
{
  int result;
  static uint8_t hash[ECC_CURVE_SIZE] = { 0xFF };
  static uint8_t public_key[ECC_CURVE_SIZE * 2];
  static uint8_t private_key[ECC_CURVE_SIZE];
  static uint8_t signature[ECC_CURVE_SIZE * 2];

  UNIT_TEST_BEGIN();

  /* enable ECC driver */
  PT_WAIT_UNTIL(&unit_test_pt, process_mutex_try_lock(ECC.get_mutex()));
  UNIT_TEST_ASSERT(!ECC.enable(ECC_CURVE));

  /* generate key pair */
  PT_SPAWN(&unit_test_pt,
           ECC.get_protothread(),
           ECC.generate_key_pair(public_key, private_key, &result));
  if(result) {
    UNIT_TEST_FAIL();
  }

  /* validate public key */
  PT_SPAWN(&unit_test_pt,
           ECC.get_protothread(),
           ECC.validate_public_key(public_key, &result));
  if(result) {
    UNIT_TEST_FAIL();
  }

  /* sign */
  PT_SPAWN(&unit_test_pt,
           ECC.get_protothread(),
           ECC.sign(hash, private_key, signature, &result));
  if(result) {
    UNIT_TEST_FAIL();
  }

  /* verify */
  PT_SPAWN(&unit_test_pt,
           ECC.get_protothread(),
           ECC.verify(signature, hash, public_key, &result));
  if(result) {
    UNIT_TEST_FAIL();
  }

  /* disable ECC driver */
  ECC.disable();

  UNIT_TEST_END();
}
/*---------------------------------------------------------------------------*/
UNIT_TEST_REGISTER(ecc_fhmqv, "FHMQV");
UNIT_TEST(ecc_fhmqv)
{
  int result;
  static uint8_t static_public_key_a[ECC_CURVE_SIZE * 2];
  static uint8_t static_private_key_a[ECC_CURVE_SIZE];
  static uint8_t ephemeral_public_key_a[ECC_CURVE_SIZE * 2];
  static uint8_t ephemeral_private_key_a[ECC_CURVE_SIZE];
  static uint8_t static_public_key_b[ECC_CURVE_SIZE * 2];
  static uint8_t static_private_key_b[ECC_CURVE_SIZE];
  static uint8_t ephemeral_public_key_b[ECC_CURVE_SIZE * 2];
  static uint8_t ephemeral_private_key_b[ECC_CURVE_SIZE];
  static uint8_t de[SHA_256_DIGEST_LENGTH];
  static uint8_t k_a[ECC_CURVE_SIZE];
  static uint8_t k_b[ECC_CURVE_SIZE];

  UNIT_TEST_BEGIN();

  /* enable ECC driver */
  PT_WAIT_UNTIL(&unit_test_pt, process_mutex_try_lock(ECC.get_mutex()));
  UNIT_TEST_ASSERT(!ECC.enable(ECC_CURVE));

  /* generate key pairs */
  PT_SPAWN(&unit_test_pt,
           ECC.get_protothread(),
           ECC.generate_key_pair(static_public_key_a,
                                 static_private_key_a,
                                 &result));
  if(result) {
    UNIT_TEST_FAIL();
  }
  PT_SPAWN(&unit_test_pt,
           ECC.get_protothread(),
           ECC.generate_key_pair(ephemeral_public_key_a,
                                 ephemeral_private_key_a,
                                 &result));
  if(result) {
    UNIT_TEST_FAIL();
  }
  PT_SPAWN(&unit_test_pt,
           ECC.get_protothread(),
           ECC.generate_key_pair(static_public_key_b,
                                 static_private_key_b,
                                 &result));
  if(result) {
    UNIT_TEST_FAIL();
  }
  PT_SPAWN(&unit_test_pt,
           ECC.get_protothread(),
           ECC.generate_key_pair(ephemeral_public_key_b,
                                 ephemeral_private_key_b,
                                 &result));
  if(result) {
    UNIT_TEST_FAIL();
  }

  /* run FHMQV */

  /* d || e */
  SHA_256.init();
  SHA_256.update(ephemeral_public_key_a, sizeof(ephemeral_public_key_a));
  SHA_256.update(ephemeral_public_key_b, sizeof(ephemeral_public_key_b));
  SHA_256.update(static_public_key_a, sizeof(static_public_key_a));
  SHA_256.update(static_public_key_b, sizeof(static_public_key_b));
  SHA_256.finalize(de);

  PT_SPAWN(&unit_test_pt,
           ECC.get_protothread(),
           ECC.generate_fhmqv_secret(static_private_key_b,
                                     ephemeral_private_key_b,
                                     static_public_key_a,
                                     ephemeral_public_key_a,
                                     de,
                                     de + (ECC_CURVE_P_256_SIZE / 2),
                                     k_b,
                                     &result));
  if(result) {
    UNIT_TEST_FAIL();
  }

  PT_SPAWN(&unit_test_pt,
           ECC.get_protothread(),
           ECC.generate_fhmqv_secret(static_private_key_a,
                                     ephemeral_private_key_a,
                                     static_public_key_b,
                                     ephemeral_public_key_b,
                                     de + (ECC_CURVE_P_256_SIZE / 2),
                                     de,
                                     k_a,
                                     &result));
  if(result) {
    UNIT_TEST_FAIL();
  }

  /* check */
  UNIT_TEST_ASSERT(!memcmp(k_a, k_b, ECC_CURVE_SIZE));

  /* disable ECC driver */
  ECC.disable();

  UNIT_TEST_END();
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
UNIT_TEST_REGISTER(ecc_ecqv, "ECQV");
UNIT_TEST(ecc_ecqv)
{
  int result;
  static uint8_t ca_public_key[ECC_CURVE_SIZE * 2];
  static uint8_t ca_private_key[ECC_CURVE_SIZE];
  static uint8_t proto_public_key[ECC_CURVE_SIZE * 2];
  static uint8_t proto_private_key[ECC_CURVE_SIZE];
  static struct cert_info cert_info;
  static uint8_t private_key_reconstruction_data[ECC_CURVE_SIZE];
  static uint8_t bobs_public_key[ECC_CURVE_SIZE * 2];
  static uint8_t bobs_private_key[ECC_CURVE_SIZE];
  static uint8_t bobs_restored_public_key[ECC_CURVE_SIZE * 2];

  UNIT_TEST_BEGIN();

  /* enable ECC driver */
  PT_WAIT_UNTIL(&unit_test_pt, process_mutex_try_lock(ECC.get_mutex()));
  UNIT_TEST_ASSERT(!ECC.enable(ECC_CURVE));

  /* CA: generate public/private key pair */
  PT_SPAWN(&unit_test_pt,
           ECC.get_protothread(),
           ECC.generate_key_pair(ca_public_key, ca_private_key, &result));
  if(result) {
    UNIT_TEST_FAIL();
  }

  /* Bob: generate proto-public/private key pair */
  PT_SPAWN(&unit_test_pt,
           ECC.get_protothread(),
           ECC.generate_key_pair(proto_public_key,
                                 proto_private_key,
                                 &result));
  if(result) {
    UNIT_TEST_FAIL();
  }

  /* CA: validate proto-public key */
  PT_SPAWN(&unit_test_pt,
           ECC.get_protothread(),
           ECC.validate_public_key(proto_public_key, &result));
  if(result) {
    UNIT_TEST_FAIL();
  }

  /* CA: generate public and private key reconstruction data */
  PT_SPAWN(&unit_test_pt,
           ECC.get_protothread(),
           ECC.generate_ecqv_certificate(proto_public_key,
                                         ca_private_key,
                                         encode_and_hash,
                                         &cert_info,
                                         private_key_reconstruction_data,
                                         &result));
  if(result) {
    UNIT_TEST_FAIL();
  }

  /* Bob: generate actual public/private key pair */
  PT_SPAWN(&unit_test_pt,
           ECC.get_protothread(),
           ECC.generate_ecqv_key_pair(proto_private_key,
                                      cert_info.hash,
                                      private_key_reconstruction_data,
                                      bobs_public_key,
                                      bobs_private_key,
                                      &result));
  if(result) {
    UNIT_TEST_FAIL();
  }

  /* Alice: restore Bob's public key */
  PT_SPAWN(&unit_test_pt,
           ECC.get_protothread(),
           ECC.validate_public_key(cert_info.reconstruction_data,
                                   &result));
  if(result) {
    UNIT_TEST_FAIL();
  }
  PT_SPAWN(&unit_test_pt,
           ECC.get_protothread(),
           ECC.restore_ecqv_public_key(cert_info.hash,
                                       cert_info.reconstruction_data,
                                       ca_public_key,
                                       bobs_restored_public_key,
                                       &result));
  if(result) {
    UNIT_TEST_FAIL();
  }

  ECC.disable();

  /* check if the restored public key matches the generated one */
  UNIT_TEST_ASSERT(!memcmp(bobs_public_key,
                           bobs_restored_public_key,
                           sizeof(bobs_public_key)));

  UNIT_TEST_END();
}
/*---------------------------------------------------------------------------*/
PROCESS_THREAD(test_process, ev, data)
{
  PROCESS_BEGIN();

  printf("Run unit-test\n");
  printf("---\n");

  UNIT_TEST_RUN(ecc_compress);
  UNIT_TEST_RUN(ecc_ecdh);
  UNIT_TEST_RUN(ecc_ecdsa);
  UNIT_TEST_RUN(ecc_fhmqv);
  UNIT_TEST_RUN(ecc_ecqv);

  if(!UNIT_TEST_PASSED(ecc_compress)
      || !UNIT_TEST_PASSED(ecc_ecdh)
      || !UNIT_TEST_PASSED(ecc_ecdsa)
      || !UNIT_TEST_PASSED(ecc_fhmqv)
      || !UNIT_TEST_PASSED(ecc_ecqv)) {
    printf("=check-me= FAILED\n");
    printf("---\n");
  }

  printf("=check-me= DONE\n");
  printf("---\n");

  PROCESS_END();
}
/*---------------------------------------------------------------------------*/
