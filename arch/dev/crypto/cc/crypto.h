/*
 * Copyright (C) 2012, Texas Instruments Incorporated - http://www.ti.com/
 * Copyright (c) 2013, ADVANSEE - http://www.advansee.com/
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
 * \addtogroup crypto
 * @{
 *
 * \defgroup cc-crypto AES/SHA cryptoprocessor
 *
 * Drivers for the AES/SHA cryptoprocessor of CCXXXX MCUs.
 * @{
 *
 * \file
 *       General definitions for the AES/SHA cryptoprocessor.
 */

#ifndef CRYPTO_H_
#define CRYPTO_H_

#include "contiki.h"
#include <stdbool.h>
#include <stdint.h>

#ifdef CRYPTO_CONF_SUPPORTS_SHA_512
#define CRYPTO_SUPPORTS_SHA_512 CRYPTO_CONF_SUPPORTS_SHA_512
#else /* CRYPTO_CONF_SUPPORTS_SHA_512 */
#define CRYPTO_SUPPORTS_SHA_512 0
#endif /* CRYPTO_CONF_SUPPORTS_SHA_512 */

/**
 * \name DMAC_CHx_CTRL registers bit fields
 * @{
 */
#define CRYPTO_DMAC_CH_CTRL_PRIO \
  0x00000002 /**< Channel priority 0: Low 1: High */
#define CRYPTO_DMAC_CH_CTRL_EN \
  0x00000001 /**< Channel enable */
/** @} */

/**
 * \name DMAC_CHx_DMALENGTH registers bit fields
 * @{
 */
#define CRYPTO_DMAC_CH_DMALENGTH_DMALEN_M \
  0x0000FFFF /**< Channel DMA length in bytes mask */
#define CRYPTO_DMAC_CH_DMALENGTH_DMALEN_S \
  0 /**< Channel DMA length in bytes shift */
/** @} */

/**
 * \name DMAC_STATUS register bit fields
 * @{
 */
#define CRYPTO_DMAC_STATUS_PORT_ERR \
  0x00020000 /**< AHB port transfer errors */
#define CRYPTO_DMAC_STATUS_CH1_ACT \
  0x00000002 /**< Channel 1 active (DMA transfer on-going) */
#define CRYPTO_DMAC_STATUS_CH0_ACT \
  0x00000001 /**< Channel 0 active (DMA transfer on-going) */
/** @} */

/**
 * \name DMAC_SW_RESET register bit fields
 * @{
 */
#define CRYPTO_DMAC_SW_RESET_SW_RESET \
  0x00000001 /**< Software reset enable */
/** @} */

/**
 * \name DMAC_BUS_CFG register bit fields
 * @{
 */
#define CRYPTO_DMAC_BUS_CFG_AHB_MST1_BURST_SIZE_4 \
  (2 << 12) /**< Maximum burst size: 4 bytes */
#define CRYPTO_DMAC_BUS_CFG_AHB_MST1_BURST_SIZE_8 \
  (3 << 12) /**< Maximum burst size: 8 bytes */
#define CRYPTO_DMAC_BUS_CFG_AHB_MST1_BURST_SIZE_16 \
  (4 << 12) /**< Maximum burst size: 16 bytes */
#define CRYPTO_DMAC_BUS_CFG_AHB_MST1_BURST_SIZE_32 \
  (5 << 12) /**< Maximum burst size: 32 bytes */
#define CRYPTO_DMAC_BUS_CFG_AHB_MST1_BURST_SIZE_64 \
  (6 << 12) /**< Maximum burst size: 64 bytes */
#define CRYPTO_DMAC_BUS_CFG_AHB_MST1_BURST_SIZE_M \
  0x0000F000 /**< Maximum burst size mask */
#define CRYPTO_DMAC_BUS_CFG_AHB_MST1_BURST_SIZE_S \
  12 /**< Maximum burst size shift */
#define CRYPTO_DMAC_BUS_CFG_AHB_MST1_IDLE_EN \
  0x00000800 /**< Idle insertion between bursts */
#define CRYPTO_DMAC_BUS_CFG_AHB_MST1_INCR_EN \
  0x00000400 /**< Fixed-length burst or single transfers */
#define CRYPTO_DMAC_BUS_CFG_AHB_MST1_LOCK_EN \
  0x00000200 /**< Locked transfers */
#define CRYPTO_DMAC_BUS_CFG_AHB_MST1_BIGEND \
  0x00000100 /**< Big endian AHB master */
/** @} */

/**
 * \name DMAC_PORT_ERR register bit fields
 * @{
 */
#define CRYPTO_DMAC_PORT_ERR_PORT1_AHB_ERROR \
  0x00001000 /**< AHB bus error */
#define CRYPTO_DMAC_PORT_ERR_PORT1_CHANNEL \
  0x00000200 /**< Last serviced channel (0 or 1) */
/** @} */

/**
 * \name DMAC_OPTIONS register bit fields
 * @{
 */
#define CRYPTO_DMAC_OPTIONS_NR_OF_CHANNELS_M \
  0x00000F00 /**< Number of channels implemented mask */
#define CRYPTO_DMAC_OPTIONS_NR_OF_CHANNELS_S \
  8 /**< Number of channels implemented shift */
#define CRYPTO_DMAC_OPTIONS_NR_OF_PORTS_M \
  0x00000007 /**< Number of ports implemented mask */
#define CRYPTO_DMAC_OPTIONS_NR_OF_PORTS_S \
  0 /**< Number of ports implemented shift */
/** @} */

/**
 * \name DMAC_VERSION register bit fields
 * @{
 */
#define CRYPTO_DMAC_VERSION_HW_MAJOR_VERSION_M \
  0x0F000000 /**< Major version number mask */
#define CRYPTO_DMAC_VERSION_HW_MAJOR_VERSION_S \
  24 /**< Major version number shift */
#define CRYPTO_DMAC_VERSION_HW_MINOR_VERSION_M \
  0x00F00000 /**< Minor version number mask */
#define CRYPTO_DMAC_VERSION_HW_MINOR_VERSION_S \
  20 /**< Minor version number shift */
#define CRYPTO_DMAC_VERSION_HW_PATCH_LEVEL_M \
  0x000F0000 /**< Patch level mask */
#define CRYPTO_DMAC_VERSION_HW_PATCH_LEVEL_S \
  16 /**< Patch level shift */
#define CRYPTO_DMAC_VERSION_EIP_NUMBER_COMPL_M \
  0x0000FF00 /**< EIP_NUMBER 1's complement mask */
#define CRYPTO_DMAC_VERSION_EIP_NUMBER_COMPL_S \
  8 /**< EIP_NUMBER 1's complement shift */
#define CRYPTO_DMAC_VERSION_EIP_NUMBER_M \
  0x000000FF /**< DMAC EIP-number mask */
#define CRYPTO_DMAC_VERSION_EIP_NUMBER_S \
  0 /**< DMAC EIP-number shift */
/** @} */

/**
 * \name KEY_STORE_SIZE register bit fields
 * @{
 */
#define CRYPTO_KEY_STORE_SIZE_KEY_SIZE_128 \
  1 /**< Key size: 128 bits */
#define CRYPTO_KEY_STORE_SIZE_KEY_SIZE_192 \
  2 /**< Key size: 192 bits */
#define CRYPTO_KEY_STORE_SIZE_KEY_SIZE_256 \
  3 /**< Key size: 256 bits */
#define CRYPTO_KEY_STORE_SIZE_KEY_SIZE_M \
  0x00000003 /**< Key size mask */
#define CRYPTO_KEY_STORE_SIZE_KEY_SIZE_S \
  0 /**< Key size shift */
/** @} */

/**
 * \name KEY_STORE_READ_AREA register bit fields
 * @{
 */
#define CRYPTO_KEY_STORE_READ_AREA_BUSY \
  0x80000000 /**< Key store operation busy */
#define CRYPTO_KEY_STORE_READ_AREA_RAM_AREA_M \
  0x0000000F /**< Key store RAM area select mask */
#define CRYPTO_KEY_STORE_READ_AREA_RAM_AREA_S \
  0 /**< Key store RAM area select shift */
/** @} */

/**
 * \name AES_CTRL register bit fields
 * @{
 */
#define CRYPTO_AES_CTRL_CONTEXT_READY \
  0x80000000 /**< Context data registers can be overwritten */
#define CRYPTO_AES_CTRL_SAVED_CONTEXT_READY \
  0x40000000 /**< AES auth. TAG and/or IV block(s) available */
#define CRYPTO_AES_CTRL_SAVE_CONTEXT \
  0x20000000 /**< Auth. TAG or result IV needs to be stored */
#define CRYPTO_AES_CTRL_GCM_CCM_CONTINUE \
  0x10000000 /**< Continue processing of GCM or CCM */
#define CRYPTO_AES_CTRL_GET_DIGEST \
  0x08000000 /**< Interrupt processing of GCM or CCM */
#define CRYPTO_AES_CTRL_GCM_CCM_CONTINUE_AAD \
  0x04000000 /**<Continue processing of GCM or CCM */
#define CRYPTO_AES_CTRL_XCBC_MAC \
  0x02000000 /**< AES-XCBC MAC mode */
#define CRYPTO_AES_CTRL_CCM_M_M \
  0x01C00000 /**< CCM auth. field length mask */
#define CRYPTO_AES_CTRL_CCM_M_S \
  22 /**< CCM auth. field length shift */
#define CRYPTO_AES_CTRL_CCM_L_M \
  0x00380000 /**< CCM length field width mask */
#define CRYPTO_AES_CTRL_CCM_L_S \
  19 /**< CCM length field width shift */
#define CRYPTO_AES_CTRL_CCM \
  0x00040000 /**< AES-CCM mode */
#define CRYPTO_AES_CTRL_GCM \
  0x00030000 /**< AES-GCM mode */
#define CRYPTO_AES_CTRL_CBC_MAC \
  0x00008000 /**< AES-CBC MAC mode */
#define CRYPTO_AES_CTRL_CTR_WIDTH_32 \
  (0 << 7) /**< CTR counter width: 32 bits */
#define CRYPTO_AES_CTRL_CTR_WIDTH_64 \
  (1 << 7) /**< CTR counter width: 64 bits */
#define CRYPTO_AES_CTRL_CTR_WIDTH_96 \
  (2 << 7) /**< CTR counter width: 96 bits */
#define CRYPTO_AES_CTRL_CTR_WIDTH_128 \
  (3 << 7) /**< CTR counter width: 128 bits */
#define CRYPTO_AES_CTRL_CTR_WIDTH_M \
  0x00000180 /**< CTR counter width mask */
#define CRYPTO_AES_CTRL_CTR_WIDTH_S \
  7 /**< CTR counter width shift */
#define CRYPTO_AES_CTRL_CTR \
  0x00000040 /**< AES-CTR mode */
#define CRYPTO_AES_CTRL_CBC \
  0x00000020 /**< AES-CBC mode */
#define CRYPTO_AES_CTRL_KEY_SIZE_128 \
  (1 << 3) /**< Key size: 128 bits */
#define CRYPTO_AES_CTRL_KEY_SIZE_192 \
  (2 << 3) /**< Key size: 192 bits */
#define CRYPTO_AES_CTRL_KEY_SIZE_256 \
  (3 << 3) /**< Key size: 256 bits */
#define CRYPTO_AES_CTRL_KEY_SIZE_M \
  0x00000018 /**< Key size mask */
#define CRYPTO_AES_CTRL_KEY_SIZE_S \
  3 /**< Key size shift */
#define CRYPTO_AES_CTRL_DIRECTION_ENCRYPT \
  0x00000004 /**< Encrypt */
#define CRYPTO_AES_CTRL_INPUT_READY \
  0x00000002 /**< AES input buffer empty */
#define CRYPTO_AES_CTRL_OUTPUT_READY \
  0x00000001 /**< AES output block available */
/** @} */

/**
 * \name AES_DATA_LENGTH_1 register bit fields
 * @{
 */
#define CRYPTO_AES_DATA_LENGTH_1_C_LENGTH_M \
  0x1FFFFFFF /**< Crypto length bits [60:32] mask */
#define CRYPTO_AES_DATA_LENGTH_1_C_LENGTH_S \
  0 /**< Crypto length bits [60:32] shift */
/** @} */

/**
 * \name HASH_IO_BUF_CTRL register bit fields
 * @{
 */
#define CRYPTO_HASH_IO_BUF_CTRL_PAD_DMA_MESSAGE \
  0x00000080 /**< Hash engine message padding required */
#define CRYPTO_HASH_IO_BUF_CTRL_GET_DIGEST \
  0x00000040 /**< Hash engine digest requested */
#define CRYPTO_HASH_IO_BUF_CTRL_PAD_MESSAGE \
  0x00000020 /**< Last message data in HASH_DATA_IN, apply hash padding */
#define CRYPTO_HASH_IO_BUF_CTRL_RFD_IN \
  0x00000004 /**< Hash engine input buffer can accept new data */
#define CRYPTO_HASH_IO_BUF_CTRL_DATA_IN_AV \
  0x00000002 /**< Start processing HASH_DATA_IN data */
#define CRYPTO_HASH_IO_BUF_CTRL_OUTPUT_FULL \
  0x00000001 /**< Output buffer registers available */
/** @} */

/**
 * \name HASH_MODE register bit fields
 * @{
 */
#define CRYPTO_HASH_MODE_SHA384_MODE \
  0x00000040 /**< SHA-384 */
#define CRYPTO_HASH_MODE_SHA512_MODE \
  0x00000020 /**< SHA-512 */
#define CRYPTO_HASH_MODE_SHA224_MODE \
  0x00000010 /**< SHA-224 */
#define CRYPTO_HASH_MODE_SHA256_MODE \
  0x00000008 /**< SHA-256 */
#define CRYPTO_HASH_MODE_NEW_HASH \
  0x00000001 /**< New hash session */
/** @} */

/**
 * \name CTRL_ALG_SEL register bit fields
 * @{
 */
#define CRYPTO_CTRL_ALG_SEL_TAG \
  0x80000000 /**< DMA operation includes TAG */
#define CRYPTO_CTRL_ALG_SEL_HASH_SHA_512 \
  0x00000008 /**< SHA-512 */
#define CRYPTO_CTRL_ALG_SEL_HASH_SHA_256 \
  0x00000004 /**< SHA-256 */
#define CRYPTO_CTRL_ALG_SEL_AES \
  0x00000002 /**< Select AES engine as DMA source/destination */
#define CRYPTO_CTRL_ALG_SEL_KEYSTORE \
  0x00000001 /**< Select Key Store as DMA destination */
/** @} */

/**
 * \name CTRL_PROT_EN register bit fields
 * @{
 */
#define CRYPTO_CTRL_PROT_EN_PROT_EN \
  0x00000001 /**< m_h_prot[1] asserted for DMA reads towards key store */
/** @} */

/**
 * \name CTRL_SW_RESET register bit fields
 * @{
 */
#define CRYPTO_CTRL_SW_RESET_SW_RESET \
  0x00000001 /**< Reset master control and key store */
/** @} */

/**
 * \name CTRL_INT_CFG register bit fields
 * @{
 */
#define CRYPTO_CTRL_INT_CFG_LEVEL \
  0x00000001 /**< Level interrupt type */
/** @} */

/**
 * \name CTRL_INT_EN register bit fields
 * @{
 */
#define CRYPTO_CTRL_INT_EN_DMA_IN_DONE \
  0x00000002 /**< DMA input done interrupt enabled */
#define CRYPTO_CTRL_INT_EN_RESULT_AV \
  0x00000001 /**< Result available interrupt enabled */
/** @} */

/**
 * \name CTRL_INT_CLR register bit fields
 * @{
 */
#define CRYPTO_CTRL_INT_CLR_DMA_BUS_ERR \
  0x80000000 /**< Clear DMA bus error status */
#define CRYPTO_CTRL_INT_CLR_KEY_ST_WR_ERR \
  0x40000000 /**< Clear key store write error status */
#define CRYPTO_CTRL_INT_CLR_KEY_ST_RD_ERR \
  0x20000000 /**< Clear key store read error status */
#define CRYPTO_CTRL_INT_CLR_DMA_IN_DONE \
  0x00000002 /**< Clear DMA in done interrupt */
#define CRYPTO_CTRL_INT_CLR_RESULT_AV \
  0x00000001 /**< Clear result available interrupt */
/** @} */

/**
 * \name CTRL_INT_SET register bit fields
 * @{
 */
#define CRYPTO_CTRL_INT_SET_DMA_IN_DONE \
  0x00000002 /**< Set DMA data in done interrupt */
#define CRYPTO_CTRL_INT_SET_RESULT_AV \
  0x00000001 /**< Set result available interrupt */
/** @} */

/**
 * \name CTRL_INT_STAT register bit fields
 * @{
 */
#define CRYPTO_CTRL_INT_STAT_DMA_BUS_ERR \
  0x80000000 /**< DMA bus error detected */
#define CRYPTO_CTRL_INT_STAT_KEY_ST_WR_ERR \
  0x40000000 /**< Write error detected */
#define CRYPTO_CTRL_INT_STAT_KEY_ST_RD_ERR \
  0x20000000 /**< Read error detected */
#define CRYPTO_CTRL_INT_STAT_DMA_IN_DONE \
  0x00000002 /**< DMA data in done interrupt status */
#define CRYPTO_CTRL_INT_STAT_RESULT_AV \
  0x00000001 /**< Result available interrupt status */
/** @} */

/**
 * \name CTRL_OPTIONS register bit fields
 * @{
 */
#define CRYPTO_CTRL_OPTIONS_TYPE_M \
  0xFF000000 /**< Device type mask */
#define CRYPTO_CTRL_OPTIONS_TYPE_S \
  24 /**< Device type shift */
#define CRYPTO_CTRL_OPTIONS_AHBINTERFACE \
  0x00010000 /**< AHB interface available */
#define CRYPTO_CTRL_OPTIONS_SHA_256 \
  0x00000100 /**< The HASH core supports SHA-256 */
#define CRYPTO_CTRL_OPTIONS_AES_CCM \
  0x00000080 /**< AES-CCM available as single operation */
#define CRYPTO_CTRL_OPTIONS_AES_GCM \
  0x00000040 /**< AES-GCM available as single operation */
#define CRYPTO_CTRL_OPTIONS_AES_256 \
  0x00000020 /**< AES core supports 256-bit keys */
#define CRYPTO_CTRL_OPTIONS_AES_128 \
  0x00000010 /**< AES core supports 128-bit keys */
#define CRYPTO_CTRL_OPTIONS_HASH \
  0x00000004 /**< HASH Core available */
#define CRYPTO_CTRL_OPTIONS_AES \
  0x00000002 /**< AES core available */
#define CRYPTO_CTRL_OPTIONS_KEYSTORE \
  0x00000001 /**< KEY STORE available */
/** @} */

/**
 * \name CTRL_VERSION register bit fields
 * @{
 */
#define CRYPTO_CTRL_VERSION_MAJOR_VERSION_M \
  0x0F000000 /**< Major version number mask */
#define CRYPTO_CTRL_VERSION_MAJOR_VERSION_S \
  24 /**< Major version number shift */
#define CRYPTO_CTRL_VERSION_MINOR_VERSION_M \
  0x00F00000 /**< Minor version number mask */
#define CRYPTO_CTRL_VERSION_MINOR_VERSION_S \
  20 /**< Minor version number shift */
#define CRYPTO_CTRL_VERSION_PATCH_LEVEL_M \
  0x000F0000 /**< Patch level mask */
#define CRYPTO_CTRL_VERSION_PATCH_LEVEL_S \
  16 /**< Patch level shift */
#define CRYPTO_CTRL_VERSION_EIP_NUMBER_COMPL_M \
  0x0000FF00 /**< EIP_NUMBER 1's complement mask */
#define CRYPTO_CTRL_VERSION_EIP_NUMBER_COMPL_S \
  8 /**< EIP_NUMBER 1's complement shift */
#define CRYPTO_CTRL_VERSION_EIP_NUMBER_M \
  0x000000FF /**< EIP-120t EIP-number mask */
#define CRYPTO_CTRL_VERSION_EIP_NUMBER_S \
  0 /**< EIP-120t EIP-number shift */
/** @} */

typedef volatile uint32_t crypto_reg_t;

struct crypto_dma_channel {
  crypto_reg_t ctrl; /**< Configures the DMA channel */
  crypto_reg_t extaddr; /**< Sets the external address */
  crypto_reg_t reserved1;
  crypto_reg_t dmalength; /**< Sets transfer length and starts DMA transfer */
  crypto_reg_t reserved2[2];
};

/** Registers of the AES/SHA cryptoprocessor. */
struct crypto {

  /** DMA controller (DMAC) 0x000-0x3FF */
  struct {
    struct crypto_dma_channel ch0;
    crypto_reg_t status; /**< Provides status and error information */
    crypto_reg_t sw_reset; /**< Resets the DMAC */
    struct crypto_dma_channel ch1;
    crypto_reg_t reserved1[16];
    crypto_reg_t bus_cfg; /**< Configures the master interface port */
    crypto_reg_t port_err; /** Provides details on errors */
    crypto_reg_t reserved2[30];
    crypto_reg_t options; /**< Provides information about supported features */
    crypto_reg_t version; /**< Provides the hardware version */
    crypto_reg_t reserved3[192];
  } dmac;

  /** Key store 0x400-0x4FF */
  struct {
    crypto_reg_t write_area; /**< Mask of the 128-bit slots to write */
    crypto_reg_t written_area; /**< Mask of written 128-bit slots */
    crypto_reg_t size; /**< Size of the keys */
    crypto_reg_t read_area; /**< Mask of the 128-bit slots to read */
    crypto_reg_t reserved[60];
  } key_store;

  /** AES engine 0x500-0x5FF */
  struct {
    crypto_reg_t key[8]; /**< Internally calculated keys */
    crypto_reg_t reserved1[8];
    crypto_reg_t iv[4]; /**< Initialization vector */
    crypto_reg_t ctrl; /**< Configuration of the AES engine */
    crypto_reg_t data_length[2]; /**< Length of the data to encrypt */
    crypto_reg_t auth_length; /**< Length of the data to authenticate */
    crypto_reg_t data_in_out[4]; /**< Input or output data */
    crypto_reg_t tag_out[4]; /**< Authentication tag */
    crypto_reg_t reserved2[21];
    crypto_reg_t ccm_aln_wrd; /**< Context for later resumption */
    crypto_reg_t blk_cnt[2]; /**< Block count for later resumption */
    crypto_reg_t reserved3[8];
  } aes;

  /** Hash engine 0x600-0x6FF */
  struct {
    crypto_reg_t data_in[CRYPTO_SUPPORTS_SHA_512 ? 32 : 16]; /**< Input data */
    crypto_reg_t io_buf_ctrl; /** Configuration of the I/O buffer */
    crypto_reg_t mode; /**< Selection of the algorithm and the resumption */
    crypto_reg_t length_in[2]; /**< Length of the input data */
    crypto_reg_t reserved1[CRYPTO_SUPPORTS_SHA_512 ? 12 : 0];
    crypto_reg_t digest[CRYPTO_SUPPORTS_SHA_512 ? 16 : 8]; /**< Hash digest */
    crypto_reg_t reserved2[CRYPTO_SUPPORTS_SHA_512 ? 0 : 36];
  } hash;

  /** Master control 0x700-0x7FF */
  struct {
    crypto_reg_t alg_sel; /**< Configures the destination of the DMAC */
    crypto_reg_t prot_en; /**< Protects DMA transfers to the key store */
    crypto_reg_t reserved1[14];
    crypto_reg_t sw_reset; /**< Resets master control and key store */
    crypto_reg_t reserved2[15];
    crypto_reg_t int_cfg; /**< Configures interrupts */
    crypto_reg_t int_en; /**< Enables interrupts */
    crypto_reg_t int_clr; /**< Acknowledges interrupts */
    crypto_reg_t int_set; /**< Tests interrupts */
    crypto_reg_t int_stat; /**< Checks for interrupts */
    crypto_reg_t reserved3[25];
    crypto_reg_t options; /**< Provides information about supported features */
    crypto_reg_t version; /**< Provides the hardware version */
  } ctrl;
};

extern struct crypto *const crypto;

/**
 * \brief Enables and resets the AES/SHA cryptoprocessor.
 */
void crypto_init(void);

/**
 * \brief Enables the AES/SHA cryptoprocessor.
 */
void crypto_enable(void);

/**
 * \brief Disables the AES/SHA cryptoprocessor.
 * \note Call this function to save power when the cryptoprocessor is unused.
 */
void crypto_disable(void);

/**
 * \brief  Checks if the AES/SHA cryptoprocessor is on.
 * \return \c true if the AES/SHA cryptoprocessor is on and \c false otherwise.
 */
bool crypto_is_enabled(void);

#endif /* CRYPTO_H_ */

/**
 * @}
 * @}
 */
