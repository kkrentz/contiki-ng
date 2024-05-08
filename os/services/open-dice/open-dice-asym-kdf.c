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
 *         Implements ASYM_KDF of the Open Profile for DICE.
 * \author
 *         Konrad Krentz <konrad.krentz@gmail.com>
 */

#include "open-dice-asym-kdf.h"
#include "lib/sha-256.h"

static uint8_t seed[OPEN_DICE_KEY_LEN];
static uint32_t counter;

/*---------------------------------------------------------------------------*/
bool
open_dice_asym_kdf_seed(const uint8_t key[static OPEN_DICE_KEY_LEN])
{
  static const uint8_t asym_salt[] = {
    0x63, 0xB6, 0xA0, 0x4D, 0x2C, 0x07, 0x7F, 0xC1,
    0x0F, 0x63, 0x9F, 0x21, 0xDA, 0x79, 0x38, 0x44,
    0x35, 0x6C, 0xC2, 0xB0, 0xB4, 0x41, 0xB3, 0xA7,
    0x71, 0x24, 0x03, 0x5C, 0x03, 0xF8, 0xE1, 0xBE,
    0x60, 0x35, 0xD3, 0x1F, 0x28, 0x28, 0x21, 0xA7,
    0x45, 0x0A, 0x02, 0x22, 0x2A, 0xB1, 0xB3, 0xCF,
    0xF1, 0x67, 0x9B, 0x05, 0xAB, 0x1C, 0xA5, 0xD1,
    0xAF, 0xFB, 0x78, 0x9C, 0xCD, 0x2B, 0x0B, 0x3B
  };
  static const char asym_info[] = "Key Pair";
  static const size_t asym_info_len = sizeof(asym_info) - 1 /* truncate \0 */;

  counter = 0;
  return sha_256_hkdf(asym_salt, sizeof(asym_salt),
                      key, OPEN_DICE_KEY_LEN,
                      (const uint8_t *)asym_info, asym_info_len,
                      seed, sizeof(seed));
}
/*---------------------------------------------------------------------------*/
bool
open_dice_asym_kdf_rand(uint8_t *result, size_t size)
{
  if(!sha_256_hkdf_expand(seed, sizeof(seed),
                          (const uint8_t *)&counter, sizeof(counter),
                          result, size)) {
    return false;
  }
  counter++;
  return true;
}
/*---------------------------------------------------------------------------*/

/** @} */
