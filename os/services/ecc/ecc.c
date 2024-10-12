/*
 * Copyright (c) 2021, Uppsala universitet.
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

/**
 * \addtogroup crypto
 * @{
 *
 * \file
 *         Adapter for uECC.
 * \author
 *         Konrad Krentz <konrad.krentz@gmail.com>
 */

#include "lib/ecc.h"
#include "lib/csprng.h"
#include "lib/sha-256.h"
#include "uECC.h"

static ecc_csprng_t temporary_csprng;
static struct pt protothread;
static const ecc_curve_t *ecc_curve;
static uECC_Curve uecc_curve;
static process_mutex_t mutex;

/*---------------------------------------------------------------------------*/
static int
csprng_adapter(uint8_t *dest, unsigned size)
{
  return csprng_rand(dest, size);
}
/*---------------------------------------------------------------------------*/
void
ecc_init(void)
{
  process_mutex_init(&mutex);
  uECC_set_rng(csprng_adapter);
}
/*---------------------------------------------------------------------------*/
process_mutex_t *
ecc_get_mutex(void)
{
  return &mutex;
}
/*---------------------------------------------------------------------------*/
int
ecc_enable(const ecc_curve_t *c)
{
  if(c == &ecc_curve_p_256) {
    uecc_curve = uECC_secp256r1();
  } else if(c == &ecc_curve_p_192) {
    uecc_curve = uECC_secp192r1();
  } else {
    process_mutex_unlock(&mutex);
    return 1;
  }
  ecc_curve = c;
  return 0;
}
/*---------------------------------------------------------------------------*/
struct pt *
ecc_get_protothread(void)
{
  return &protothread;
}
/*---------------------------------------------------------------------------*/
PT_THREAD(ecc_validate_public_key(const uint8_t *public_key,
                                  int *const result))
{
  PT_BEGIN(&protothread);

  *result = !uECC_valid_public_key(public_key, uecc_curve);

  PT_END(&protothread);
}
/*---------------------------------------------------------------------------*/
void
ecc_compress_public_key(const uint8_t *uncompressed_public_key,
                        uint8_t *compressed_public_key)
{
  uECC_compress(uncompressed_public_key, compressed_public_key, uecc_curve);
}
/*---------------------------------------------------------------------------*/
PT_THREAD(ecc_decompress_public_key(const uint8_t *compressed_public_key,
                                    uint8_t *uncompressed_public_key,
                                    int *const result))
{
  PT_BEGIN(&protothread);

  uECC_decompress(compressed_public_key,
                  uncompressed_public_key,
                  uecc_curve);
  *result = 0;

  PT_END(&protothread);
}
/*---------------------------------------------------------------------------*/
PT_THREAD(ecc_sign(const uint8_t *message_hash,
                   const uint8_t *private_key,
                   uint8_t *signature,
                   int *const result))
{
  PT_BEGIN(&protothread);

  *result = !uECC_sign(private_key,
                       message_hash,
                       ecc_curve->bytes,
                       signature,
                       uecc_curve);

  PT_END(&protothread);
}
/*---------------------------------------------------------------------------*/
PT_THREAD(ecc_verify(const uint8_t *signature,
                     const uint8_t *message_hash,
                     const uint8_t *public_key,
                     int *const result))
{
  PT_BEGIN(&protothread);

  *result = !uECC_verify(public_key,
                         message_hash,
                         ecc_curve->bytes,
                         signature,
                         uecc_curve);

  PT_END(&protothread);
}
/*---------------------------------------------------------------------------*/
PT_THREAD(ecc_generate_key_pair(uint8_t *public_key,
                                uint8_t *private_key,
                                int *const result))
{
  PT_BEGIN(&protothread);

  *result = !uECC_make_key(public_key,
                           private_key,
                           uecc_curve);

  PT_END(&protothread);
}
/*---------------------------------------------------------------------------*/
static int
temporary_csprng_adapter(uint8_t *dest, unsigned size)
{
  return temporary_csprng(dest, size);
}
/*---------------------------------------------------------------------------*/
PT_THREAD(ecc_generate_key_pair_deterministic(ecc_csprng_t csprng,
                                              uint8_t *public_key,
                                              uint8_t *private_key,
                                              int *const result))
{
  PT_BEGIN(&protothread);

  temporary_csprng = csprng;
  *result = !uECC_make_key_deterministic(temporary_csprng_adapter,
                                         public_key,
                                         private_key,
                                         uecc_curve);

  PT_END(&protothread);
}
/*---------------------------------------------------------------------------*/
PT_THREAD(ecc_generate_shared_secret(const uint8_t *public_key,
                                     const uint8_t *private_key,
                                     uint8_t *shared_secret,
                                     int *const result))
{
  PT_BEGIN(&protothread);

  *result = !uECC_shared_secret(public_key,
                                private_key,
                                shared_secret,
                                uecc_curve);

  PT_END(&protothread);
}
/*---------------------------------------------------------------------------*/
PT_THREAD(ecc_generate_fhmqv_secret(const uint8_t *static_private_key,
                                    const uint8_t *ephemeral_private_key,
                                    const uint8_t *static_public_key,
                                    const uint8_t *ephemeral_public_key,
                                    const uint8_t *d,
                                    const uint8_t *e,
                                    uint8_t *shared_secret,
                                    int *const result))
{
  PT_BEGIN(&protothread);

  *result = !uECC_shared_fhmqv_secret(static_private_key,
                                      ephemeral_private_key,
                                      static_public_key,
                                      ephemeral_public_key,
                                      d,
                                      e,
                                      shared_secret,
                                      uecc_curve);

  PT_END(&protothread);
}
/*---------------------------------------------------------------------------*/
PT_THREAD(ecc_issue_ecqv_certificate(
              const uint8_t *proto_public_key,
              const uint8_t *ca_private_key,
              ecc_encode_ecqv_certificate_and_hash_t encode_and_hash,
              void *opaque,
              uint8_t *private_key_reconstruction_data,
              int *const result))
{
  PT_BEGIN(&protothread);

  *result = !uECC_issue_ecqv_certificate(proto_public_key,
                                         ca_private_key,
                                         encode_and_hash,
                                         opaque,
                                         private_key_reconstruction_data,
                                         uecc_curve);

  PT_END(&protothread);
}
/*---------------------------------------------------------------------------*/
PT_THREAD(ecc_generate_ecqv_key_pair(
              const uint8_t *proto_private_key,
              const uint8_t *certificate_hash,
              const uint8_t *private_key_reconstruction_data,
              uint8_t *public_key,
              uint8_t *private_key,
              int *const result))
{
  PT_BEGIN(&protothread);

  *result = !uECC_generate_ecqv_key_pair(proto_private_key,
                                         certificate_hash,
                                         ecc_curve->bytes,
                                         private_key_reconstruction_data,
                                         public_key,
                                         private_key,
                                         uecc_curve);

  PT_END(&protothread);
}
/*---------------------------------------------------------------------------*/
PT_THREAD(ecc_reconstruct_ecqv_public_key(
              const uint8_t *certificate_hash,
              const uint8_t *public_key_reconstruction_data,
              const uint8_t *ca_public_key,
              uint8_t *public_key,
              int *const result))
{
  PT_BEGIN(&protothread);

  *result = !uECC_reconstruct_ecqv_public_key(certificate_hash,
                                              ecc_curve->bytes,
                                              public_key_reconstruction_data,
                                              ca_public_key,
                                              public_key,
                                              uecc_curve);

  PT_END(&protothread);
}
/*---------------------------------------------------------------------------*/
void
ecc_disable(void)
{
  process_mutex_unlock(&mutex);
}
/*---------------------------------------------------------------------------*/

/** @} */
