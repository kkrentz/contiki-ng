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
 *         Resembles TinyDICE's root of trust.
 * \author
 *         Konrad Krentz <konrad.krentz@gmail.com>
 */

#include "tiny-dice-rot.h"
#include "tiny-dice-l0.h"
#include "lib/sha-256.h"

/*---------------------------------------------------------------------------*/
bool
tiny_dice_rot_boot(void)
{
  static const uint8_t uds[TINY_DICE_UDS_SIZE];
  static const uint8_t tci_l0[TINY_DICE_TCI_SIZE];
  uint8_t cdi_l0[TINY_DICE_CDI_SIZE];
  if(!sha_256_hkdf_expand(uds, sizeof(uds),
                          tci_l0, sizeof(tci_l0),
                          cdi_l0, sizeof(cdi_l0))) {
    return false;
  }
  tiny_dice_l0_set_cdi_l0(cdi_l0);
  return true;
}
/*---------------------------------------------------------------------------*/

/** @} */
