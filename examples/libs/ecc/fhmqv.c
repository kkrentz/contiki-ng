/*
 * Copyright (c) 2022, Uppsala universitet.
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
 *         Demonstrates the usage of FHMQV.
 * \author
 *         Konrad Krentz <konrad.krentz@gmail.com>
 */

#include "contiki.h"
#include "lib/ecc.h"
#include "lib/sha-256.h"
#include <string.h>

#include "sys/log.h"
#define LOG_MODULE "FHMQV"
#define LOG_LEVEL LOG_LEVEL_DBG

#define ECC_CURVE (&ecc_curve_p_256)
#define ECC_CURVE_SIZE (ECC_CURVE_P_256_SIZE)

PROCESS(fhmqv_process, "FHMQV");
AUTOSTART_PROCESSES(&fhmqv_process);

/*---------------------------------------------------------------------------*/
PROCESS_THREAD(fhmqv_process, ev, data)
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

  PROCESS_BEGIN();

  /* enable ECC driver */
  PROCESS_WAIT_UNTIL(process_mutex_try_lock(ecc_get_mutex()));
  if(ecc_enable(ECC_CURVE)) {
    LOG_ERR("enable failed\n");
    PROCESS_EXIT();
  }

  LOG_INFO("generating key pairs\n");
  PROCESS_PT_SPAWN(ecc_get_protothread(),
                   ecc_generate_key_pair(static_public_key_a,
                                         static_private_key_a,
                                         &result));
  if(result) {
    LOG_ERR("generate_key_pair failed\n");
    goto exit;
  }
  PROCESS_PT_SPAWN(ecc_get_protothread(),
                   ecc_generate_key_pair(ephemeral_public_key_a,
                                         ephemeral_private_key_a,
                                         &result));
  if(result) {
    LOG_ERR("generate_key_pair failed\n");
    goto exit;
  }
  PROCESS_PT_SPAWN(ecc_get_protothread(),
                   ecc_generate_key_pair(static_public_key_b,
                                         static_private_key_b,
                                         &result));
  if(result) {
    LOG_ERR("generate_key_pair failed\n");
    goto exit;
  }
  PROCESS_PT_SPAWN(ecc_get_protothread(),
                   ecc_generate_key_pair(ephemeral_public_key_b,
                                         ephemeral_private_key_b,
                                         &result));
  if(result) {
    LOG_ERR("generate_key_pair failed\n");
    goto exit;
  }

  LOG_INFO("running FHMQV\n");

  /* d || e */
  SHA_256.init();
  SHA_256.update(ephemeral_public_key_a, sizeof(ephemeral_public_key_a));
  SHA_256.update(ephemeral_public_key_b, sizeof(ephemeral_public_key_b));
  SHA_256.update(static_public_key_a, sizeof(static_public_key_a));
  SHA_256.update(static_public_key_b, sizeof(static_public_key_b));
  SHA_256.finalize(de);

  PROCESS_PT_SPAWN(ecc_get_protothread(),
                   ecc_generate_fhmqv_secret(static_private_key_b,
                                             ephemeral_private_key_b,
                                             static_public_key_a,
                                             ephemeral_public_key_a,
                                             de,
                                             de + ECC_CURVE_SIZE / 2,
                                             k_b,
                                             &result));
  if(result) {
    LOG_ERR("ecc_generate_fhmqv_secret failed\n");
    goto exit;
  }

  PROCESS_PT_SPAWN(ecc_get_protothread(),
                   ecc_generate_fhmqv_secret(static_private_key_a,
                                             ephemeral_private_key_a,
                                             static_public_key_b,
                                             ephemeral_public_key_b,
                                             de + ECC_CURVE_SIZE / 2,
                                             de,
                                             k_a,
                                             &result));
  if(result) {
    LOG_ERR("ecc_generate_fhmqv_secret failed\n");
    goto exit;
  }

  if(memcmp(k_a, k_b, ECC_CURVE_SIZE)) {
    LOG_ERR("unequal\n");
  } else {
    LOG_INFO("OK\n");
  }

exit:
  ecc_disable();
  PROCESS_END();
}
/*---------------------------------------------------------------------------*/
