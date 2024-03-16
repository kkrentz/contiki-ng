/*
 * Original file:
 * Copyright (C) 2012 Texas Instruments Incorporated - http://www.ti.com/
 * All rights reserved.
 *
 * Port to Contiki:
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

typedef volatile uint32_t crypto_reg_t;

#ifdef CRYPTO_CONF_SUPPORTS_SHA_512
#define CRYPTO_SUPPORTS_SHA_512 CRYPTO_CONF_SUPPORTS_SHA_512
#else /* CRYPTO_CONF_SUPPORTS_SHA_512 */
#define CRYPTO_SUPPORTS_SHA_512 0
#endif /* CRYPTO_CONF_SUPPORTS_SHA_512 */

/*---------------------------------------------------------------------------*/
/** \name AES_DMAC_CHx_CTRL registers bit fields
 * @{
 */
#define AES_DMAC_CH_CTRL_PRIO   0x00000002 /**< Channel priority 0: Low 1: High */
#define AES_DMAC_CH_CTRL_EN     0x00000001 /**< Channel enable */
/** @} */
/*---------------------------------------------------------------------------*/
/** \name AES_DMAC_CHx_DMALENGTH registers bit fields
 * @{
 */
#define AES_DMAC_CH_DMALENGTH_DMALEN_M \
                                0x0000FFFF /**< Channel DMA length in bytes mask */
#define AES_DMAC_CH_DMALENGTH_DMALEN_S 0   /**< Channel DMA length in bytes shift */
/** @} */
/*---------------------------------------------------------------------------*/
/** \name AES_DMAC_STATUS register bit fields
 * @{
 */
#define AES_DMAC_STATUS_PORT_ERR \
                                0x00020000 /**< AHB port transfer errors */
#define AES_DMAC_STATUS_CH1_ACT 0x00000002 /**< Channel 1 active (DMA transfer on-going) */
#define AES_DMAC_STATUS_CH0_ACT 0x00000001 /**< Channel 0 active (DMA transfer on-going) */
/** @} */
/*---------------------------------------------------------------------------*/
/** \name AES_DMAC_SWRES register bit fields
 * @{
 */
#define AES_DMAC_SWRES_SWRES    0x00000001 /**< Software reset enable */
/** @} */
/*---------------------------------------------------------------------------*/
/** \name AES_DMAC_MST_RUNPARAMS register bit fields
 * @{
 */
#define AES_DMAC_MST_RUNPARAMS_AHB_MST1_BURST_SIZE_4 \
                                (2 << 12)  /**< Maximum burst size: 4 bytes */
#define AES_DMAC_MST_RUNPARAMS_AHB_MST1_BURST_SIZE_8 \
                                (3 << 12)  /**< Maximum burst size: 8 bytes */
#define AES_DMAC_MST_RUNPARAMS_AHB_MST1_BURST_SIZE_16 \
                                (4 << 12)  /**< Maximum burst size: 16 bytes */
#define AES_DMAC_MST_RUNPARAMS_AHB_MST1_BURST_SIZE_32 \
                                (5 << 12)  /**< Maximum burst size: 32 bytes */
#define AES_DMAC_MST_RUNPARAMS_AHB_MST1_BURST_SIZE_64 \
                                (6 << 12)  /**< Maximum burst size: 64 bytes */
#define AES_DMAC_MST_RUNPARAMS_AHB_MST1_BURST_SIZE_M \
                                0x0000F000 /**< Maximum burst size mask */
#define AES_DMAC_MST_RUNPARAMS_AHB_MST1_BURST_SIZE_S \
                                12         /**< Maximum burst size shift */
#define AES_DMAC_MST_RUNPARAMS_AHB_MST1_IDLE_EN \
                                0x00000800 /**< Idle insertion between bursts */
#define AES_DMAC_MST_RUNPARAMS_AHB_MST1_INCR_EN \
                                0x00000400 /**< Fixed-length burst or single transfers */
#define AES_DMAC_MST_RUNPARAMS_AHB_MST1_LOCK_EN \
                                0x00000200 /**< Locked transfers */
#define AES_DMAC_MST_RUNPARAMS_AHB_MST1_BIGEND \
                                0x00000100 /**< Big endian AHB master */
/** @} */
/*---------------------------------------------------------------------------*/
/** \name AES_DMAC_PERSR register bit fields
 * @{
 */
#define AES_DMAC_PERSR_PORT1_AHB_ERROR \
                                0x00001000 /**< AHB bus error */
#define AES_DMAC_PERSR_PORT1_CHANNEL \
                                0x00000200 /**< Last serviced channel (0 or 1) */
/** @} */
/*---------------------------------------------------------------------------*/
/** \name AES_DMAC_OPTIONS register bit fields
 * @{
 */
#define AES_DMAC_OPTIONS_NR_OF_CHANNELS_M \
                                0x00000F00 /**< Number of channels implemented mask */
#define AES_DMAC_OPTIONS_NR_OF_CHANNELS_S \
                                8          /**< Number of channels implemented shift */
#define AES_DMAC_OPTIONS_NR_OF_PORTS_M \
                                0x00000007 /**< Number of ports implemented mask */
#define AES_DMAC_OPTIONS_NR_OF_PORTS_S 0   /**< Number of ports implemented shift */
/** @} */
/*---------------------------------------------------------------------------*/
/** \name AES_DMAC_VERSION register bit fields
 * @{
 */
#define AES_DMAC_VERSION_HW_MAJOR_VERSION_M \
                                0x0F000000 /**< Major version number mask */
#define AES_DMAC_VERSION_HW_MAJOR_VERSION_S \
                                24         /**< Major version number shift */
#define AES_DMAC_VERSION_HW_MINOR_VERSION_M \
                                0x00F00000 /**< Minor version number mask */
#define AES_DMAC_VERSION_HW_MINOR_VERSION_S \
                                20         /**< Minor version number shift */
#define AES_DMAC_VERSION_HW_PATCH_LEVEL_M \
                                0x000F0000 /**< Patch level mask */
#define AES_DMAC_VERSION_HW_PATCH_LEVEL_S \
                                16         /**< Patch level shift */
#define AES_DMAC_VERSION_EIP_NUMBER_COMPL_M \
                                0x0000FF00 /**< EIP_NUMBER 1's complement mask */
#define AES_DMAC_VERSION_EIP_NUMBER_COMPL_S \
                                8          /**< EIP_NUMBER 1's complement shift */
#define AES_DMAC_VERSION_EIP_NUMBER_M \
                                0x000000FF /**< DMAC EIP-number mask */
#define AES_DMAC_VERSION_EIP_NUMBER_S 0    /**< DMAC EIP-number shift */
/** @} */
/*---------------------------------------------------------------------------*/
/** \name AES_KEY_STORE_SIZE register bit fields
 * @{
 */
#define AES_KEY_STORE_SIZE_KEY_SIZE_128 1  /**< Key size: 128 bits */
#define AES_KEY_STORE_SIZE_KEY_SIZE_192 2  /**< Key size: 192 bits */
#define AES_KEY_STORE_SIZE_KEY_SIZE_256 3  /**< Key size: 256 bits */
#define AES_KEY_STORE_SIZE_KEY_SIZE_M \
                                0x00000003 /**< Key size mask */
#define AES_KEY_STORE_SIZE_KEY_SIZE_S 0    /**< Key size shift */
/** @} */
/*---------------------------------------------------------------------------*/
/** \name AES_KEY_STORE_READ_AREA register bit fields
 * @{
 */
#define AES_KEY_STORE_READ_AREA_BUSY \
                                0x80000000 /**< Key store operation busy */
#define AES_KEY_STORE_READ_AREA_RAM_AREA_M \
                                0x0000000F /**< Key store RAM area select mask */
#define AES_KEY_STORE_READ_AREA_RAM_AREA_S \
                                0          /**< Key store RAM area select shift */
/** @} */
/*---------------------------------------------------------------------------*/
/** \name AES_AES_CTRL register bit fields
 * @{
 */
#define AES_AES_CTRL_CONTEXT_READY \
                                0x80000000 /**< Context data registers can be overwritten */
#define AES_AES_CTRL_SAVED_CONTEXT_READY \
                                0x40000000 /**< AES auth. TAG and/or IV block(s) available */
#define AES_AES_CTRL_SAVE_CONTEXT \
                                0x20000000 /**< Auth. TAG or result IV needs to be stored */
#define AES_AES_CTRL_CCM_M_M    0x01C00000 /**< CCM auth. field length mask */
#define AES_AES_CTRL_CCM_M_S    22         /**< CCM auth. field length shift */
#define AES_AES_CTRL_CCM_L_M    0x00380000 /**< CCM length field width mask */
#define AES_AES_CTRL_CCM_L_S    19         /**< CCM length field width shift */
#define AES_AES_CTRL_CCM        0x00040000 /**< AES-CCM mode */
#define AES_AES_CTRL_GCM        0x00030000 /**< AES-GCM mode */
#define AES_AES_CTRL_CBC_MAC    0x00008000 /**< AES-CBC MAC mode */
#define AES_AES_CTRL_CTR_WIDTH_32 (0 << 7) /**< CTR counter width: 32 bits */
#define AES_AES_CTRL_CTR_WIDTH_64 (1 << 7) /**< CTR counter width: 64 bits */
#define AES_AES_CTRL_CTR_WIDTH_96 (2 << 7) /**< CTR counter width: 96 bits */
#define AES_AES_CTRL_CTR_WIDTH_128 \
                                (3 << 7)   /**< CTR counter width: 128 bits */
#define AES_AES_CTRL_CTR_WIDTH_M \
                                0x00000180 /**< CTR counter width mask */
#define AES_AES_CTRL_CTR_WIDTH_S 7         /**< CTR counter width shift */
#define AES_AES_CTRL_CTR        0x00000040 /**< AES-CTR mode */
#define AES_AES_CTRL_CBC        0x00000020 /**< AES-CBC mode */
#define AES_AES_CTRL_KEY_SIZE_128 (1 << 3) /**< Key size: 128 bits */
#define AES_AES_CTRL_KEY_SIZE_192 (2 << 3) /**< Key size: 192 bits */
#define AES_AES_CTRL_KEY_SIZE_256 (3 << 3) /**< Key size: 256 bits */
#define AES_AES_CTRL_KEY_SIZE_M 0x00000018 /**< Key size mask */
#define AES_AES_CTRL_KEY_SIZE_S 3          /**< Key size shift */
#define AES_AES_CTRL_DIRECTION_ENCRYPT \
                                0x00000004 /**< Encrypt */
#define AES_AES_CTRL_INPUT_READY \
                                0x00000002 /**< AES input buffer empty */
#define AES_AES_CTRL_OUTPUT_READY \
                                0x00000001 /**< AES output block available */
/** @} */
/*---------------------------------------------------------------------------*/
/** \name AES_AES_C_LENGTH_1 register bit fields
 * @{
 */
#define AES_AES_C_LENGTH_1_C_LENGTH_M \
                                0x1FFFFFFF /**< Crypto length bits [60:32] mask */
#define AES_AES_C_LENGTH_1_C_LENGTH_S 0    /**< Crypto length bits [60:32] shift */
/** @} */
/*---------------------------------------------------------------------------*/
/** \name AES_HASH_IO_BUF_CTRL register bit fields
 * @{
 */
#define AES_HASH_IO_BUF_CTRL_PAD_DMA_MESSAGE \
                                0x00000080 /**< Hash engine message padding required */
#define AES_HASH_IO_BUF_CTRL_GET_DIGEST \
                                0x00000040 /**< Hash engine digest requested */
#define AES_HASH_IO_BUF_CTRL_PAD_MESSAGE \
                                0x00000020 /**< Last message data in HASH_DATA_IN, apply hash padding */
#define AES_HASH_IO_BUF_CTRL_RFD_IN \
                                0x00000004 /**< Hash engine input buffer can accept new data */
#define AES_HASH_IO_BUF_CTRL_DATA_IN_AV \
                                0x00000002 /**< Start processing HASH_DATA_IN data */
#define AES_HASH_IO_BUF_CTRL_OUTPUT_FULL \
                                0x00000001 /**< Output buffer registers available */
/** @} */
/*---------------------------------------------------------------------------*/
/** \name AES_HASH_MODE_IN register bit fields
 * @{
 */
#define AES_HASH_MODE_IN_SHA256_MODE \
                                0x00000008 /**< Hash mode */
#define AES_HASH_MODE_IN_NEW_HASH \
                                0x00000001 /**< New hash session */
/** @} */
/*---------------------------------------------------------------------------*/
/** \name AES_CTRL_ALG_SEL register bit fields
 * @{
 */
#define AES_CTRL_ALG_SEL_TAG    0x80000000 /**< DMA operation includes TAG */
#define AES_CTRL_ALG_SEL_HASH   0x00000004 /**< Select hash engine as DMA destination */
#define AES_CTRL_ALG_SEL_AES    0x00000002 /**< Select AES engine as DMA source/destination */
#define AES_CTRL_ALG_SEL_KEYSTORE \
                                0x00000001 /**< Select Key Store as DMA destination */
/** @} */
/*---------------------------------------------------------------------------*/
/** \name AES_CTRL_PROT_EN register bit fields
 * @{
 */
#define AES_CTRL_PROT_EN_PROT_EN \
                                0x00000001 /**< m_h_prot[1] asserted for DMA reads towards key store */
/** @} */
/*---------------------------------------------------------------------------*/
/** \name AES_CTRL_SW_RESET register bit fields
 * @{
 */
#define AES_CTRL_SW_RESET_SW_RESET \
                                0x00000001 /**< Reset master control and key store */
/** @} */
/*---------------------------------------------------------------------------*/
/** \name AES_CTRL_INT_CFG register bit fields
 * @{
 */
#define AES_CTRL_INT_CFG_LEVEL  0x00000001 /**< Level interrupt type */
/** @} */
/*---------------------------------------------------------------------------*/
/** \name AES_CTRL_INT_EN register bit fields
 * @{
 */
#define AES_CTRL_INT_EN_DMA_IN_DONE \
                                0x00000002 /**< DMA input done interrupt enabled */
#define AES_CTRL_INT_EN_RESULT_AV \
                                0x00000001 /**< Result available interrupt enabled */
/** @} */
/*---------------------------------------------------------------------------*/
/** \name AES_CTRL_INT_CLR register bit fields
 * @{
 */
#define AES_CTRL_INT_CLR_DMA_BUS_ERR \
                                0x80000000 /**< Clear DMA bus error status */
#define AES_CTRL_INT_CLR_KEY_ST_WR_ERR \
                                0x40000000 /**< Clear key store write error status */
#define AES_CTRL_INT_CLR_KEY_ST_RD_ERR \
                                0x20000000 /**< Clear key store read error status */
#define AES_CTRL_INT_CLR_DMA_IN_DONE \
                                0x00000002 /**< Clear DMA in done interrupt */
#define AES_CTRL_INT_CLR_RESULT_AV \
                                0x00000001 /**< Clear result available interrupt */
/** @} */
/*---------------------------------------------------------------------------*/
/** \name AES_CTRL_INT_SET register bit fields
 * @{
 */
#define AES_CTRL_INT_SET_DMA_IN_DONE \
                                0x00000002 /**< Set DMA data in done interrupt */
#define AES_CTRL_INT_SET_RESULT_AV \
                                0x00000001 /**< Set result available interrupt */
/** @} */
/*---------------------------------------------------------------------------*/
/** \name AES_CTRL_INT_STAT register bit fields
 * @{
 */
#define AES_CTRL_INT_STAT_DMA_BUS_ERR \
                                0x80000000 /**< DMA bus error detected */
#define AES_CTRL_INT_STAT_KEY_ST_WR_ERR \
                                0x40000000 /**< Write error detected */
#define AES_CTRL_INT_STAT_KEY_ST_RD_ERR \
                                0x20000000 /**< Read error detected */
#define AES_CTRL_INT_STAT_DMA_IN_DONE \
                                0x00000002 /**< DMA data in done interrupt status */
#define AES_CTRL_INT_STAT_RESULT_AV \
                                0x00000001 /**< Result available interrupt status */
/** @} */
/*---------------------------------------------------------------------------*/
/** \name AES_CTRL_OPTIONS register bit fields
 * @{
 */
#define AES_CTRL_OPTIONS_TYPE_M 0xFF000000 /**< Device type mask */
#define AES_CTRL_OPTIONS_TYPE_S 24         /**< Device type shift */
#define AES_CTRL_OPTIONS_AHBINTERFACE \
                                0x00010000 /**< AHB interface available */
#define AES_CTRL_OPTIONS_SHA_256 \
                                0x00000100 /**< The HASH core supports SHA-256 */
#define AES_CTRL_OPTIONS_AES_CCM \
                                0x00000080 /**< AES-CCM available as single operation */
#define AES_CTRL_OPTIONS_AES_GCM \
                                0x00000040 /**< AES-GCM available as single operation */
#define AES_CTRL_OPTIONS_AES_256 \
                                0x00000020 /**< AES core supports 256-bit keys */
#define AES_CTRL_OPTIONS_AES_128 \
                                0x00000010 /**< AES core supports 128-bit keys */
#define AES_CTRL_OPTIONS_HASH   0x00000004 /**< HASH Core available */
#define AES_CTRL_OPTIONS_AES    0x00000002 /**< AES core available */
#define AES_CTRL_OPTIONS_KEYSTORE \
                                0x00000001 /**< KEY STORE available */
/** @} */
/*---------------------------------------------------------------------------*/
/** \name AES_CTRL_VERSION register bit fields
 * @{
 */
#define AES_CTRL_VERSION_MAJOR_VERSION_M \
                                0x0F000000 /**< Major version number mask */
#define AES_CTRL_VERSION_MAJOR_VERSION_S \
                                24         /**< Major version number shift */
#define AES_CTRL_VERSION_MINOR_VERSION_M \
                                0x00F00000 /**< Minor version number mask */
#define AES_CTRL_VERSION_MINOR_VERSION_S \
                                20         /**< Minor version number shift */
#define AES_CTRL_VERSION_PATCH_LEVEL_M \
                                0x000F0000 /**< Patch level mask */
#define AES_CTRL_VERSION_PATCH_LEVEL_S 16  /**< Patch level shift */
#define AES_CTRL_VERSION_EIP_NUMBER_COMPL_M \
                                0x0000FF00 /**< EIP_NUMBER 1's complement mask */
#define AES_CTRL_VERSION_EIP_NUMBER_COMPL_S \
                                8          /**< EIP_NUMBER 1's complement shift */
#define AES_CTRL_VERSION_EIP_NUMBER_M \
                                0x000000FF /**< EIP-120t EIP-number mask */
#define AES_CTRL_VERSION_EIP_NUMBER_S 0    /**< EIP-120t EIP-number shift */
/** @} */
/*---------------------------------------------------------------------------*/

/** Registers of the AES/SHA cryptoprocessor. */
struct crypto {
  /* DMA controller */
  crypto_reg_t dmac_ch0_ctrl;
  crypto_reg_t dmac_ch0_extaddr;
  crypto_reg_t dmac_reserved1;
  crypto_reg_t dmac_ch0_dmalength;
  crypto_reg_t dmac_reserved2[2];
  crypto_reg_t dmac_status;
  crypto_reg_t dmac_swres;
  crypto_reg_t dmac_ch1_ctrl;
  crypto_reg_t dmac_ch1_extaddr;
  crypto_reg_t dmac_reserved3;
  crypto_reg_t dmac_ch1_dmalength;
  crypto_reg_t dmac_reserved4[18];
  crypto_reg_t dmac_mst_runparams; /**< aka DMABUSCFG */
  crypto_reg_t dmac_persr;
  crypto_reg_t dmac_reserved5[30];
  crypto_reg_t dmac_options;
  crypto_reg_t dmac_version;
  crypto_reg_t dmac_reserved6[192];

  /* Key store 0x400-0x4FF */
  crypto_reg_t key_store_write_area;
  crypto_reg_t key_store_written_area;
  crypto_reg_t key_store_size;
  crypto_reg_t key_store_read_area;
  crypto_reg_t key_store_reserved[60];

  /* AES engine 0x500-0x5FF */
  crypto_reg_t aes_key2[4];
  crypto_reg_t aes_key3[4];
  crypto_reg_t aes_reserved1[8];
  crypto_reg_t aes_iv_0;
  crypto_reg_t aes_iv_1;
  crypto_reg_t aes_iv_2;
  crypto_reg_t aes_iv_3;
  crypto_reg_t aes_ctrl;
  crypto_reg_t aes_c_length_0;
  crypto_reg_t aes_c_length_1;
  crypto_reg_t aes_auth_length;
  crypto_reg_t aes_data_in_out_0;
  crypto_reg_t aes_data_in_out_1;
  crypto_reg_t aes_data_in_out_2;
  crypto_reg_t aes_data_in_out_3;
  crypto_reg_t aes_tag_out_0;
  crypto_reg_t aes_tag_out_1;
  crypto_reg_t aes_tag_out_2;
  crypto_reg_t aes_tag_out_3;
  crypto_reg_t aes_reserved2[32];

  /* Hash engine 0x600-0x6FF */
  crypto_reg_t hash_data_in[CRYPTO_SUPPORTS_SHA_512 ? 32 : 16];
  crypto_reg_t hash_io_buf_ctrl;
  crypto_reg_t hash_mode_in;
  crypto_reg_t hash_length_in_l;
  crypto_reg_t hash_length_in_h;
  crypto_reg_t reserved1[CRYPTO_SUPPORTS_SHA_512 ? 12 : 0];
  crypto_reg_t hash_digest[CRYPTO_SUPPORTS_SHA_512 ? 16 : 8];
  crypto_reg_t reserved2[CRYPTO_SUPPORTS_SHA_512 ? 0 : 36];

  /* Master control 0x700 – 0x7FF */
  crypto_reg_t ctrl_alg_sel;
  crypto_reg_t ctrl_prot_en;
  crypto_reg_t ctrl_reserved1[14];
  crypto_reg_t ctrl_sw_reset;
  crypto_reg_t ctrl_reserved2[15];
  crypto_reg_t ctrl_int_cfg;
  crypto_reg_t ctrl_int_en;
  crypto_reg_t ctrl_int_clr;
  crypto_reg_t ctrl_int_set;
  crypto_reg_t ctrl_int_stat;
  crypto_reg_t ctrl_reserved3[25];
  crypto_reg_t ctrl_option;
  crypto_reg_t ctrl_version;
};

extern struct crypto *crypto;

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
