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
 * 3. Neither the name of the Institute nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * This file is part of the Contiki operating system.
 *
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
  static uint8_t spkA[ECC_CURVE_SIZE * 2];
  static uint8_t sskA[ECC_CURVE_SIZE];
  static uint8_t epkA[ECC_CURVE_SIZE * 2];
  static uint8_t eskA[ECC_CURVE_SIZE];
  static uint8_t spkB[ECC_CURVE_SIZE * 2];
  static uint8_t sskB[ECC_CURVE_SIZE];
  static uint8_t epkB[ECC_CURVE_SIZE * 2];
  static uint8_t eskB[ECC_CURVE_SIZE];
  static uint8_t d[SHA_256_DIGEST_LENGTH];
  static uint8_t e[SHA_256_DIGEST_LENGTH];
  static uint8_t kA[ECC_CURVE_SIZE];
  static uint8_t kB[ECC_CURVE_SIZE];

  PROCESS_BEGIN();

  /* enable ECC driver */
  PROCESS_MUTEX_WAIT(process_pt, ECC.get_mutex());
  if(ECC.enable(ECC_CURVE)) {
    LOG_ERR("enable failed\n");
    PROCESS_EXIT();
  }

  LOG_INFO("generating key pairs\n");
  PROCESS_PT_SPAWN(ECC.get_protothread(),
                   ECC.generate_key_pair(sskA, spkA, &result));
  if(result) {
    LOG_ERR("generate_key_pair failed\n");
    PROCESS_EXIT();
  }
  PROCESS_PT_SPAWN(ECC.get_protothread(),
                   ECC.generate_key_pair(eskA, epkA, &result));
  if(result) {
    LOG_ERR("generate_key_pair failed\n");
    PROCESS_EXIT();
  }
  PROCESS_PT_SPAWN(ECC.get_protothread(),
                   ECC.generate_key_pair(sskB, spkB, &result));
  if(result) {
    LOG_ERR("generate_key_pair failed\n");
    PROCESS_EXIT();
  }
  PROCESS_PT_SPAWN(ECC.get_protothread(),
                   ECC.generate_key_pair(eskB, epkB, &result));
  if(result) {
    LOG_ERR("generate_key_pair failed\n");
    PROCESS_EXIT();
  }

  LOG_INFO("running FHMQV\n");

  /* d || e */
  SHA_256.init();
  SHA_256.update(epkA, sizeof(epkA));
  SHA_256.update(epkB, sizeof(epkB));
  SHA_256.update(spkA, sizeof(spkA));
  SHA_256.update(spkB, sizeof(spkB));
  SHA_256.finalize(d);
  memcpy(e + SHA_256_DIGEST_LENGTH / 2, d, SHA_256_DIGEST_LENGTH / 2);
  memset(e, 0, SHA_256_DIGEST_LENGTH / 2);
  memset(d, 0, SHA_256_DIGEST_LENGTH / 2);

  PROCESS_PT_SPAWN(ECC.get_protothread(),
                   ECC.generate_fhmqv_secret(kB,
                                             sskB,
                                             eskB,
                                             spkA,
                                             epkA,
                                             e,
                                             d,
                                             &result));
  if(result) {
    LOG_ERR("ECC.generate_fhmqv_secret failed\n");
    PROCESS_EXIT();
  }

  PROCESS_PT_SPAWN(ECC.get_protothread(),
                   ECC.generate_fhmqv_secret(kA,
                                             sskA,
                                             eskA,
                                             spkB,
                                             epkB,
                                             d,
                                             e,
                                             &result));
  if(result) {
    LOG_ERR("ECC.generate_fhmqv_secret failed\n");
    PROCESS_EXIT();
  }

  ECC.disable();

  if(memcmp(kB, kA, ECC_CURVE_SIZE)) {
    LOG_ERR("unequal\n");
  } else {
    LOG_INFO("OK\n");
  }

  PROCESS_END();
}
/*---------------------------------------------------------------------------*/
