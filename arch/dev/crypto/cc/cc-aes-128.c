/*
 * Copyright (c) 2015, Hasso-Plattner-Institut.
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
 * \addtogroup cc-crypto
 * @{
 *
 * \file
 *         Implementation of the AES-128 driver for CCXXXX MCUs.
 * \author
 *         Konrad Krentz <konrad.krentz@gmail.com>
 */

#include "dev/crypto/cc/cc-aes-128.h"
#include "dev/crypto/cc/crypto.h"
#include "lib/assert.h"
#include <stdbool.h>

/* Log configuration */
#include "sys/log.h"
#define LOG_MODULE "cc-aes-128"
#define LOG_LEVEL LOG_LEVEL_NONE

uint_fast8_t cc_aes_128_active_key_area = CC_AES_128_KEY_AREA;

/*---------------------------------------------------------------------------*/
static bool
set_key(const uint8_t key[static AES_128_KEY_LENGTH])
{
  bool result = false;
  bool was_crypto_enabled = crypto_is_enabled();
  if(!was_crypto_enabled) {
    crypto_enable();
  }

  /* all previous interrupts should have been acknowledged */
  assert(!crypto->ctrl_int_stat);

  /* set up AES interrupts */
  crypto->ctrl_int_cfg = AES_CTRL_INT_CFG_LEVEL;
  crypto->ctrl_int_en = AES_CTRL_INT_EN_RESULT_AV;

  /* enable DMA path to the key store module */
  crypto->ctrl_alg_sel = AES_CTRL_ALG_SEL_KEYSTORE;

  /* configure key store module (area, size) - note that setting
   * crypto->key_store_size is unnecessary because 128 bits is the reset value
   * because AES_KEY_STORE_SIZE_KEY_SIZE_128 is the reset value. Moreover, this
   * would clear all other loaded keys. */
  /* clear key to write */
  uint32_t area_mask = 1 << cc_aes_128_active_key_area;
  crypto->key_store_written_area = area_mask;
  /* enable key to write */
  crypto->key_store_write_area = area_mask;

  /* configure DMAC */
  crypto->dmac_ch0_ctrl = AES_DMAC_CH_CTRL_EN; /* enable DMA channel 0 */
  uint8_t aligned_key[AES_128_KEY_LENGTH]__attribute__((aligned(4)));
  memcpy(aligned_key, key, sizeof(aligned_key));
  /* set base address of the aligned key in external memory */
  crypto->dmac_ch0_extaddr = (uintptr_t)aligned_key;
  /* total key length in bytes (e.g. 16 for 1 x 128-bit key) */
  crypto->dmac_ch0_dmalength = AES_128_KEY_LENGTH;

  /* wait for completion */
  while(!(crypto->ctrl_int_stat & AES_CTRL_INT_STAT_RESULT_AV));

  /* acknowledge the interrupt */
  crypto->ctrl_int_clr = AES_CTRL_INT_CLR_RESULT_AV;

  /* check for absence of errors in DMA and key store */
  uint32_t errors = crypto->ctrl_int_stat
                    & (AES_CTRL_INT_STAT_DMA_BUS_ERR
                       | AES_CTRL_INT_STAT_KEY_ST_WR_ERR);
  if(errors) {
    LOG_ERR("error at line %d\n", __LINE__);
    /* clear errors */
    crypto->ctrl_int_clr = errors;
    goto exit;
  }

  /* check that key was written */
  if(!(crypto->key_store_written_area & area_mask)) {
    LOG_ERR("error at line %d\n", __LINE__);
    goto exit;
  }

  result = true;

exit:
  /* all interrupts should have been acknowledged */
  assert(!crypto->ctrl_int_stat);

  /* disable master control/DMA clock */
  crypto->ctrl_alg_sel = 0;

  if(!was_crypto_enabled) {
    crypto_disable();
  }
  return result;
}
/*---------------------------------------------------------------------------*/
static bool
encrypt(uint8_t plaintext_and_result[static AES_128_BLOCK_SIZE])
{
  bool result = false;
  bool was_crypto_enabled = crypto_is_enabled();
  if(!was_crypto_enabled) {
    crypto_enable();
  }

  /* all previous interrupts should have been acknowledged */
  assert(!crypto->ctrl_int_stat);

  /* set up AES interrupts */
  crypto->ctrl_int_cfg = AES_CTRL_INT_CFG_LEVEL;
  crypto->ctrl_int_en = AES_CTRL_INT_EN_RESULT_AV;

  /* enable the DMA path to the AES engine */
  crypto->ctrl_alg_sel = AES_CTRL_ALG_SEL_AES;

  /* configure the key store to provide pre-loaded AES key */
  crypto->key_store_read_area = cc_aes_128_active_key_area;

  /* wait until the key is loaded to the AES module */
  while(crypto->key_store_read_area & AES_KEY_STORE_READ_AREA_BUSY);

  /* check if the key was loaded without errors */
  if(crypto->ctrl_int_stat & AES_CTRL_INT_STAT_KEY_ST_RD_ERR) {
    LOG_ERR("error at line %d\n", __LINE__);
    /* clear error */
    crypto->ctrl_int_clr = AES_CTRL_INT_STAT_KEY_ST_RD_ERR;
    goto exit;
  }

  /* configure AES engine */
  crypto->aes_ctrl = AES_AES_CTRL_DIRECTION_ENCRYPT;
  /* write length of the message (lo) */
  crypto->aes_c_length_0 = AES_128_BLOCK_SIZE;
  /* write length of the message (hi) */
  crypto->aes_c_length_1 = 0;

  /* configure DMAC */
  /* enable DMA channel 0 */
  crypto->dmac_ch0_ctrl = AES_DMAC_CH_CTRL_EN;
  /* base address of the input data in external memory */
  crypto->dmac_ch0_extaddr = (uintptr_t)plaintext_and_result;
  /* length of the input data to be transferred */
  crypto->dmac_ch0_dmalength = AES_128_BLOCK_SIZE;
  /* enable DMA channel 1 */
  crypto->dmac_ch1_ctrl = AES_DMAC_CH_CTRL_EN;
  /* base address of the output data in external memory */
  crypto->dmac_ch1_extaddr = (uintptr_t)plaintext_and_result;
  /* length of the output data to be transferred */
  crypto->dmac_ch1_dmalength = AES_128_BLOCK_SIZE;

  /* wait for completion */
  while(!(crypto->ctrl_int_stat & AES_CTRL_INT_STAT_RESULT_AV));

  /* acknowledge the interrupt */
  crypto->ctrl_int_clr = AES_CTRL_INT_CLR_RESULT_AV;

  /* check for errors in DMA and key store */
  uint32_t errors = crypto->ctrl_int_stat
                    & (AES_CTRL_INT_STAT_DMA_BUS_ERR
                       | AES_CTRL_INT_STAT_KEY_ST_RD_ERR);
  if(errors) {
    LOG_ERR("error at line %d\n", __LINE__);
    /* clear errors */
    crypto->ctrl_int_clr = errors;
    goto exit;
  }

  result = true;

exit:
  /* all interrupts should have been acknowledged */
  assert(!crypto->ctrl_int_stat);

  /* disable master control/DMA clock */
  crypto->ctrl_alg_sel = 0;

  if(!was_crypto_enabled) {
    crypto_disable();
  }
  return result;
}
/*---------------------------------------------------------------------------*/
const struct aes_128_driver cc_aes_128_driver = {
  set_key,
  encrypt,
  aes_128_get_lock,
  aes_128_release_lock
};
/*---------------------------------------------------------------------------*/

/** @} */
