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
 */

/**
 * \file
 *         Header file of ECC
 * \author
 *         Konrad Krentz <konrad.krentz@gmail.com>
 */

#ifndef ECC_H_
#define ECC_H_

#include "contiki.h"

#ifdef ECC_CONF
#define ECC ECC_CONF
#else /* ECC_CONF */
#define ECC ecc_driver
#endif /* ECC_CONF */

#define ECC_BYTES (32)
#define ECC_SIGNATURE_LEN (ECC_BYTES * 2)

struct ecc_driver {
  void (* enable)(void);
  struct pt *(* get_protothread)(void);
  PT_THREAD((* validate_public_key)(
      const uint8_t public_key[static ECC_BYTES * 2],
      int *result));
  void (* compress_public_key)(
      const uint8_t uncompressed_public_key[static ECC_BYTES * 2],
      uint8_t compressed_public_key[static ECC_BYTES + 1]);
  PT_THREAD((* decompress_public_key)(
      const uint8_t compressed_public_key[static ECC_BYTES + 1],
      uint8_t uncompressed_public_key[static ECC_BYTES * 2],
      int *result));
  PT_THREAD((* sign)(
      uint8_t signature[static ECC_SIGNATURE_LEN],
      const uint8_t message_hash[static ECC_BYTES],
      const uint8_t private_key[static ECC_BYTES],
      int *result));
  PT_THREAD((* verify)(
      const uint8_t signature[static ECC_SIGNATURE_LEN],
      const uint8_t message_hash[static ECC_BYTES],
      const uint8_t public_key[static ECC_BYTES * 2],
      int *result));
  PT_THREAD((* generate_key_pair)(
      uint8_t private_key[static ECC_BYTES],
      uint8_t public_key[static ECC_BYTES * 2],
      int *result));
  PT_THREAD((* generate_shared_secret)(
      const uint8_t private_key[static ECC_BYTES],
      const uint8_t public_key[static ECC_BYTES * 2],
      uint8_t shared_secret[static ECC_BYTES],
      int *result));
  PT_THREAD((* generate_fhmqv_secret)(
      uint8_t shared_secret[static ECC_BYTES],
      const uint8_t static_private_key[static ECC_BYTES],
      const uint8_t ephemeral_private_key[static ECC_BYTES],
      const uint8_t static_public_key[static ECC_BYTES * 2],
      const uint8_t ephemeral_public_key[static ECC_BYTES * 2],
      const uint8_t d[static ECC_BYTES],
      const uint8_t e[static ECC_BYTES],
      int *result));
  void (* disable)(void);
};

extern const struct ecc_driver ECC;

#endif /* ECC_H_ */
