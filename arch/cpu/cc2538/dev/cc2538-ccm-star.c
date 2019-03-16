/*
 * Copyright (c) 2019, Hasso-Plattner-Institut.
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
 *
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
 * \addtogroup cc2538-ccm-star
 * @{
 *
 * \file
 *         Implementation of the CCM* driver for the CC2538 SoC
 * \author
 *         Konrad Krentz <konrad.krentz@gmail.com>
 */

#include "contiki.h"
#include "dev/cc2538-aes-128.h"
#include "dev/cc2538-ccm-star.h"
#include "dev/aes.h"

#define CCM_L 2
#define CCM_FLAGS_LEN 1

/* Log configuration */
#include "sys/log.h"
#define LOG_MODULE "cc2538-ccm-star"
#define LOG_LEVEL LOG_LEVEL_NONE

typedef union {
  uint8_t u8[AES_128_BLOCK_SIZE];
  uint32_t u32[AES_128_BLOCK_SIZE / sizeof(uint32_t)];
} block_t;

/*---------------------------------------------------------------------------*/
static void
set_key(const uint8_t *key)
{
  cc2538_aes_128_driver.set_key(key);
}
/*---------------------------------------------------------------------------*/
static void
aead(const uint8_t *nonce,
    uint8_t *m, uint8_t m_len,
    const uint8_t *a, uint8_t a_len,
    uint8_t *result, uint8_t mic_len,
    int forward)
{
  int was_crypto_enabled;
  block_t iv;
  block_t tag;

  was_crypto_enabled = CRYPTO_IS_ENABLED();
  if(!was_crypto_enabled) {
    crypto_enable();
  }

  /* set up AES interrupts */
  REG(AES_CTRL_INT_CFG) = AES_CTRL_INT_CFG_LEVEL;
  REG(AES_CTRL_INT_EN) = AES_CTRL_INT_EN_DMA_IN_DONE | AES_CTRL_INT_EN_RESULT_AV;

  /* configure the master control module */
  REG(AES_CTRL_ALG_SEL) = AES_CTRL_ALG_SEL_AES; /* enable the DMA path to the AES engine */
  REG(AES_CTRL_INT_CLR) = AES_CTRL_INT_CLR_RESULT_AV; /* clear any outstanding events */

  /* configure the key store to provide pre-loaded AES key */
  REG(AES_KEY_STORE_READ_AREA) = CC2538_AES_128_KEY_AREA;

  /* Prepare the IV while waiting */
  iv.u8[0] = CCM_L - 1;
  memcpy(iv.u8 + CCM_FLAGS_LEN, nonce, CCM_STAR_NONCE_LENGTH);
  memset(iv.u8 + CCM_FLAGS_LEN + CCM_STAR_NONCE_LENGTH, 0, AES_128_BLOCK_SIZE - CCM_FLAGS_LEN - CCM_STAR_NONCE_LENGTH);

  /* wait until the key is loaded to the AES module */
  while(REG(AES_KEY_STORE_READ_AREA) & AES_KEY_STORE_READ_AREA_BUSY);

  /* check that the key is loaded without errors */
  if(REG(AES_CTRL_INT_STAT) & AES_CTRL_INT_STAT_KEY_ST_RD_ERR) {
    LOG_ERR("error at line %d\n", __LINE__);
    sys_ctrl_reset();
  }

  /* write the initialization vector */
  REG(AES_AES_IV_0) = iv.u32[0];
  REG(AES_AES_IV_1) = iv.u32[1];
  REG(AES_AES_IV_2) = iv.u32[2];
  REG(AES_AES_IV_3) = iv.u32[3];

  /* configure AES engine */
  REG(AES_AES_CTRL) = AES_AES_CTRL_SAVE_CONTEXT /* Save context */
      | (((MAX(mic_len, 2) - 2) >> 1) << AES_AES_CTRL_CCM_M_S) /* M */
      | ((CCM_L - 1) << AES_AES_CTRL_CCM_L_S) /* L */
      | AES_AES_CTRL_CCM /* CCM */
      | AES_AES_CTRL_CTR_WIDTH_128 /* CTR width 128 */
      | AES_AES_CTRL_CTR /* CTR */
      | (forward ? AES_AES_CTRL_DIRECTION_ENCRYPT : 0); /* En/decryption */
  REG(AES_AES_C_LENGTH_0) = m_len; /* write length of the message (lo) */
  REG(AES_AES_C_LENGTH_1) = 0; /* write length of the message (hi) */
  REG(AES_AES_AUTH_LENGTH) = a_len; /* write the length of the AAD data block (may be non-block size aligned) */

  /* configure DMAC to fetch the AAD data */
  REG(AES_DMAC_CH0_CTRL) = AES_DMAC_CH_CTRL_EN; /* enable DMA channel 0 */
  REG(AES_DMAC_CH0_EXTADDR) = (uint32_t)a; /* base address of the AAD input data in ext. memory */
  REG(AES_DMAC_CH0_DMALENGTH) = a_len; /* AAD data length in bytes, equal to the AAD length len({aad data}) (may be non-block size aligned) */

  /* wait for completion of the AAD data transfer */
  while(!(REG(AES_CTRL_INT_STAT) & AES_CTRL_INT_STAT_DMA_IN_DONE));

  /* check for the absence of errors */
  if(REG(AES_CTRL_INT_STAT) & AES_CTRL_INT_STAT_DMA_BUS_ERR) {
    LOG_ERR("error at line %d\n", __LINE__);
    sys_ctrl_reset();
  }

  /* configure DMAC */
  REG(AES_DMAC_CH0_CTRL) = AES_DMAC_CH_CTRL_EN; /* enable DMA channel 0 */
  REG(AES_DMAC_CH0_EXTADDR) = (uint32_t)m; /* base address of the payload data in ext. memory */
  REG(AES_DMAC_CH0_DMALENGTH) = m_len; /* payload data length in bytes, equal to the message length len({crypto_data} */
  REG(AES_DMAC_CH1_CTRL) = AES_DMAC_CH_CTRL_EN; /* enable DMA channel 1 */
  REG(AES_DMAC_CH1_EXTADDR) = (uint32_t)m; /* base address of the output data buffer */
  REG(AES_DMAC_CH1_DMALENGTH) = m_len; /* output data length in bytes, equal to the result data length (may be non-block size aligned) */

  /* wait for completion */
  while(!(REG(AES_CTRL_INT_STAT) & AES_CTRL_INT_STAT_RESULT_AV));

  /* check for absence of errors */
  if(REG(AES_CTRL_INT_STAT) & AES_CTRL_INT_STAT_DMA_BUS_ERR) {
    LOG_ERR("error at line %d\n", __LINE__);
    sys_ctrl_reset();
  }

  /* disable master control/DMA clock */
  REG(AES_CTRL_ALG_SEL) = 0x00000000;

  /* read tag */
  while(!(REG(AES_AES_CTRL) & AES_AES_CTRL_SAVED_CONTEXT_READY)); /* wait for the context ready bit [30] */
  tag.u32[0] = REG(AES_AES_TAG_OUT_0);
  tag.u32[1] = REG(AES_AES_TAG_OUT_1);
  tag.u32[2] = REG(AES_AES_TAG_OUT_2);
  tag.u32[3] = REG(AES_AES_TAG_OUT_3); /* this read clears the ‘saved_context_ready’ flag */

  memcpy(result, tag.u8, mic_len);

  if(!was_crypto_enabled) {
    crypto_disable();
  }
}
/*---------------------------------------------------------------------------*/
const struct ccm_star_driver cc2538_ccm_star_driver = {
  set_key,
  aead
};
/*---------------------------------------------------------------------------*/

/** @} */
