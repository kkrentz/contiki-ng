/*
 * Original file:
 * Copyright (C) 2012 Texas Instruments Incorporated - http://www.ti.com/
 * All rights reserved.
 *
 * Port to Contiki:
 * Copyright (c) 2013, ADVANSEE - http://www.advansee.com/
 * All rights reserved.
 *
 * Adaptation to platform-independent API:
 * Copyright (c) 2021, Uppsala universitet
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
 * \addtogroup cc-crypto
 * @{
 *
 * \file
 *       Implementation of the SHA-256 driver for CCXXXX MCUs.
 */

#include "dev/crypto/cc/cc-sha-256.h"
#include "dev/crypto/cc/cc-aes-128.h"
#include "dev/crypto/cc/crypto.h"
#include "lib/aes-128.h"
#include "lib/assert.h"
#include <stdbool.h>

/* Log configuration */
#include "sys/log.h"
#define LOG_MODULE "cc-sha-256"
#define LOG_LEVEL LOG_LEVEL_NONE

/**
 * \brief       Counts the number of elements of an array.
 * \param array The array.
 * \return      The number of elements of the array.
 */
#define ARRAY_LENGTH(array) (sizeof(array) / sizeof((array)[0]))

static const uint8_t empty_digest[SHA_256_DIGEST_LENGTH] = {
  0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
  0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
  0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
  0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55
};
static sha_256_checkpoint_t checkpoint;
static bool was_crypto_enabled;

/*---------------------------------------------------------------------------*/
static bool
is_valid_source_address(uintptr_t address)
{
  static const uintptr_t sram_base = 0x20000000;
  return address >= sram_base;
}
/*---------------------------------------------------------------------------*/
static void
enable_crypto(void)
{
  while(!cc_aes_128_driver.get_lock());
  was_crypto_enabled = crypto_is_enabled();
  if(!was_crypto_enabled) {
    crypto_enable();
  }
  /* enable DMA path to the SHA-256 engine + Digest readout */
  crypto->ctrl_alg_sel = AES_CTRL_ALG_SEL_TAG | AES_CTRL_ALG_SEL_HASH;
}
/*---------------------------------------------------------------------------*/
static void
disable_crypto(void)
{
  /* disable master control/DMA clock */
  crypto->ctrl_alg_sel = 0;
  if(!was_crypto_enabled) {
    crypto_disable();
  }
  cc_aes_128_driver.release_lock();
}
/*---------------------------------------------------------------------------*/
static void
do_hash(const uint8_t *data, size_t len,
        void *digest, uint64_t final_bit_count)
{
  /* DMA fails if data does not reside in RAM  */
  assert(is_valid_source_address((uintptr_t)data));
  /* all previous interrupts should have been acknowledged */
  assert(!crypto->ctrl_int_stat);

  /* set up AES interrupts */
  crypto->ctrl_int_cfg = AES_CTRL_INT_CFG_LEVEL;
  crypto->ctrl_int_en = AES_CTRL_INT_EN_RESULT_AV;

  if(checkpoint.bit_count) {
    /* configure resumed hash session */
    crypto->hash_mode_in = AES_HASH_MODE_IN_SHA256_MODE;
    for(size_t i = 0; i < ARRAY_LENGTH(checkpoint.state); i++) {
      crypto->hash_digest[i] = checkpoint.state[i];
    }
  } else {
    /* configure new hash session */
    crypto->hash_mode_in = AES_HASH_MODE_IN_SHA256_MODE
                           | AES_HASH_MODE_IN_NEW_HASH;
  }

  if(final_bit_count) {
    /* configure for generating the final hash */
    crypto->hash_length_in_l = final_bit_count;
    crypto->hash_length_in_h = final_bit_count >> 32;
    crypto->hash_io_buf_ctrl = AES_HASH_IO_BUF_CTRL_PAD_DMA_MESSAGE;
  }

  /* enable DMA channel 0 for message data */
  crypto->dmac_ch0_ctrl = AES_DMAC_CH_CTRL_EN;
  /* set base address of the data in ext. memory */
  crypto->dmac_ch0_extaddr = (uintptr_t)data;
  /* set input data length in bytes */
  crypto->dmac_ch0_dmalength = len;
  /* enable DMA channel 1 for result digest */
  crypto->dmac_ch1_ctrl = AES_DMAC_CH_CTRL_EN;
  /* set base address of the digest buffer */
  crypto->dmac_ch1_extaddr = (uintptr_t)digest;
  /* set length of the result digest */
  crypto->dmac_ch1_dmalength = SHA_256_DIGEST_LENGTH;

  /* wait for operation done (hash and DMAC are ready) */
  while(!(crypto->ctrl_int_stat & AES_CTRL_INT_STAT_RESULT_AV));

  /* clear the interrupt */
  crypto->ctrl_int_clr = AES_CTRL_INT_CLR_RESULT_AV;

  /* check for the absence of errors */
  if(crypto->ctrl_int_stat & AES_CTRL_INT_STAT_DMA_BUS_ERR) {
    LOG_ERR("error at line %d\n", __LINE__);
    crypto->ctrl_int_clr = AES_CTRL_INT_STAT_DMA_BUS_ERR;
  }

  /* all interrupts should have been acknowledged */
  assert(!crypto->ctrl_int_stat);
}
/*---------------------------------------------------------------------------*/
static void
init(void)
{
  enable_crypto();
}
/*---------------------------------------------------------------------------*/
static void
update(const uint8_t *data, size_t len)
{
  while(len) {
    size_t n;
    if(!checkpoint.buf_len && (len > SHA_256_BLOCK_SIZE)) {
      if(is_valid_source_address((uintptr_t)data)) {
        n = (len - 1) & ~(SHA_256_BLOCK_SIZE - 1);
        do_hash(data, n, checkpoint.state, 0);
      } else {
        n = SHA_256_BLOCK_SIZE;
        memcpy(checkpoint.buf, data, n);
        do_hash(checkpoint.buf, n, checkpoint.state, 0);
      }
      checkpoint.bit_count += n << 3;
      data += n;
      len -= n;
    } else {
      n = MIN(len, SHA_256_BLOCK_SIZE - checkpoint.buf_len);
      memcpy(checkpoint.buf + checkpoint.buf_len, data, n);
      checkpoint.buf_len += n;
      data += n;
      len -= n;
      if((checkpoint.buf_len == SHA_256_BLOCK_SIZE) && len) {
        do_hash(checkpoint.buf, SHA_256_BLOCK_SIZE, checkpoint.state, 0);
        checkpoint.bit_count += SHA_256_BLOCK_SIZE << 3;
        checkpoint.buf_len = 0;
      }
    }
  }
}
/*---------------------------------------------------------------------------*/
static void
finalize(uint8_t digest[static SHA_256_DIGEST_LENGTH])
{
  uint64_t final_bit_count = checkpoint.bit_count + (checkpoint.buf_len << 3);
  if(!final_bit_count) {
    /* the CC2538 would freeze otherwise */
    memcpy(digest, empty_digest, sizeof(empty_digest));
  } else {
    do_hash(checkpoint.buf, checkpoint.buf_len, digest, final_bit_count);
  }
  disable_crypto();
  checkpoint.buf_len = 0;
  checkpoint.bit_count = 0;
}
/*---------------------------------------------------------------------------*/
static void
create_checkpoint(sha_256_checkpoint_t *cp)
{
  disable_crypto();
  memcpy(cp, &checkpoint, sizeof(*cp));
}
/*---------------------------------------------------------------------------*/
static void
restore_checkpoint(const sha_256_checkpoint_t *cp)
{
  memcpy(&checkpoint, cp, sizeof(checkpoint));
  enable_crypto();
}
/*---------------------------------------------------------------------------*/
static void
hash(const uint8_t *data, size_t len,
     uint8_t digest[static SHA_256_DIGEST_LENGTH])
{
  if(!len) {
    /* the CC2538 would freeze otherwise */
    memcpy(digest, empty_digest, sizeof(empty_digest));
  } else if(is_valid_source_address((uintptr_t)data)) {
    enable_crypto();
    do_hash(data, len, digest, len << 3);
    disable_crypto();
  } else {
    sha_256_hash(data, len, digest);
  }
}
/*---------------------------------------------------------------------------*/
const struct sha_256_driver cc_sha_256_driver = {
  init,
  update,
  finalize,
  create_checkpoint,
  restore_checkpoint,
  hash,
};
/*---------------------------------------------------------------------------*/

/** @} */
