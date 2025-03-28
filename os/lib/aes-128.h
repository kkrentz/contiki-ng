/*
 * Copyright (c) 2013, Hasso-Plattner-Institut.
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
 * \addtogroup crypto
 * @{
 * \file
 *         AES-128.
 * \author
 *         Konrad Krentz <konrad.krentz@gmail.com>
 */

#ifndef AES_128_H_
#define AES_128_H_

#include "contiki.h"
#include <stdbool.h>
#include <stdint.h>

#define AES_128_BLOCK_SIZE 16
#define AES_128_KEY_LENGTH 16

#ifdef AES_128_CONF
#define AES_128            AES_128_CONF
#else /* AES_128_CONF */
#define AES_128            aes_128_driver
#endif /* AES_128_CONF */

#ifndef AES_128_CONF_WITH_LOCKING
#define AES_128_CONF_WITH_LOCKING 0
#endif /* AES_128_CONF_WITH_LOCKING */

/**
 * Structure of AES drivers.
 */
struct aes_128_driver {

  /**
   * \brief Sets the current key.
   * \return True on success.
   */
  bool (* set_key)(const uint8_t key[static AES_128_KEY_LENGTH]);

  /**
   * \brief Encrypts.
   * \return True on success.
   */
  bool (* encrypt)(uint8_t plaintext_and_result[static AES_128_BLOCK_SIZE]);

  /**
   * \brief Reserves exclusive access.
   */
  bool (* get_lock)(void);

  /**
   * \brief Unblocks access.
   */
  void (* release_lock)(void);
};

extern const struct aes_128_driver AES_128;

bool aes_128_get_lock(void);
void aes_128_release_lock(void);

#endif /* AES_128_H_ */

/** @} */
