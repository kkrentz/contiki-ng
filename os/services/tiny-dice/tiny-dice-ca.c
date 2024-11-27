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
 *         Issuance of TinyDICE Cert_L0 certificates.
 * \author
 *         Konrad Krentz <konrad.krentz@gmail.com>
 */

#include "tiny-dice-ca.h"
#include "tiny-dice.h"
#include "tiny-dice-csprng.h"
#include "tiny-dice-rot.h"

/* Log configuration */
#include "sys/log.h"
#define LOG_MODULE "TinyDICE"
#define LOG_LEVEL LOG_LEVEL_DBG

static const uint8_t ca_private_key[] = {
  0x0d, 0xd8, 0x82, 0x73, 0x55, 0xa6, 0x8e, 0x96,
  0x0b, 0x91, 0x5e, 0x92, 0x78, 0x52, 0x15, 0x35,
  0x1f, 0x9b, 0x8b, 0xea, 0x2e, 0x68, 0x97, 0x91,
  0x70, 0x4d, 0x74, 0x05, 0x9c, 0x50, 0x9e, 0x41
};

/*---------------------------------------------------------------------------*/
static int
encode_and_hash_cert_l0(const uint8_t *reconstruction_data,
                        void *opaque,
                        uint8_t *certificate_hash)
{
  tiny_dice_cert_t *cert_l0 = (tiny_dice_cert_t *)opaque;

  /* set reconstruction data of Cert_L0 */
  ecc_compress_public_key(reconstruction_data, cert_l0->reconstruction_data);

  /* encode Cert_L0 */
  uint8_t cert_l0_bytes[TINY_DICE_MAX_CERT_SIZE];
  cbor_writer_state_t state;
  cbor_init_writer(&state, cert_l0_bytes, sizeof(cert_l0_bytes));
  tiny_dice_write_cert(&state, cert_l0);
  size_t cert_l0_size = cbor_end_writer(&state);
  if(!cert_l0_size) {
    return 0;
  }

  /* hash Cert_L0 */
  SHA_256.hash(cert_l0_bytes, cert_l0_size, certificate_hash);
  LOG_DBG("Cert_L0: %zu bytes\n", cert_l0_size);

  return 1;
}
/*---------------------------------------------------------------------------*/
PT_THREAD(tiny_dice_ca_request(
    tiny_dice_cert_t *cert_l0,
    uint8_t private_key_reconstruction_data_l0[static ECC_CURVE_P_256_SIZE],
    int *const result))
{
  PT_BEGIN(&tiny_dice_pt);

  /* enable ECC */
  PT_WAIT_UNTIL(&tiny_dice_pt, process_mutex_try_lock(ecc_get_mutex()));
  if(ecc_enable(&ecc_curve_p_256)) {
    LOG_ERR("ecc_enable failed\n");
    *result = 1;
    PT_EXIT(&tiny_dice_pt);
  }

  /* deterministically generate proto-DeviceID (not usually done by the CA) */
  uint8_t proto_device_id_public_key[2 * ECC_CURVE_P_256_SIZE];
  {
    uint8_t proto_device_id_private_key[ECC_CURVE_P_256_SIZE];

    tiny_dice_rot_boot();
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
  }

  /* issue Cert_L0 */
  PT_SPAWN(&tiny_dice_pt,
           ecc_get_protothread(),
           ecc_generate_ecqv_certificate(proto_device_id_public_key,
                                         ca_private_key,
                                         encode_and_hash_cert_l0,
                                         cert_l0,
                                         private_key_reconstruction_data_l0,
                                         result));
  if(*result) {
    LOG_ERR("ecc_generate_ecqv_certificate failed\n");
    goto error;
  }

error:
  ecc_disable();

  PT_END(&tiny_dice_pt);
}
/*---------------------------------------------------------------------------*/

/** @} */
