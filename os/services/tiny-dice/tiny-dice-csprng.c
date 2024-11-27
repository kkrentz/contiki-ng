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
 *         Generates cryptographic random numbers deterministically.
 * \author
 *         Konrad Krentz <konrad.krentz@gmail.com>
 */

#include "tiny-dice-csprng.h"
#include "lib/sha-256.h"
#include <string.h>

static uint8_t seed[TINY_DICE_CDI_SIZE];
static struct info {
  uint32_t counter;
  uint8_t salt[TINY_DICE_TCI_SIZE];
} info;

/*---------------------------------------------------------------------------*/
void
tiny_dice_csprng_seed(const uint8_t cdi_l0[static TINY_DICE_CDI_SIZE])
{
  memcpy(seed, cdi_l0, sizeof(seed));
  tiny_dice_csprng_reset();
}
/*---------------------------------------------------------------------------*/
void
tiny_dice_csprng_reset(void)
{
  memset(&info, 0, sizeof(info));
}
/*---------------------------------------------------------------------------*/
bool
tiny_dice_csprng_rand(uint8_t *result, size_t size)
{
  sha_256_hkdf_expand(seed, sizeof(seed),
                      (const uint8_t *)&info, sizeof(info),
                      result, size);
  info.counter++;
  return true;
}
/*---------------------------------------------------------------------------*/
void
tiny_dice_csprng_salt(const uint8_t tci_l1[static TINY_DICE_TCI_SIZE])
{
  memcpy(info.salt, tci_l1, sizeof(info.salt));
}
/*---------------------------------------------------------------------------*/

/** @} */
