/*
 * Copyright (c) 2012, Texas Instruments Incorporated - http://www.ti.com/
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
 * \addtogroup cc2538-rf
 * @{
 *
 * \file
 * Implementation of the cc2538 RF driver
 */
#include "contiki.h"
#include "dev/radio.h"
#include "sys/clock.h"
#include "sys/rtimer.h"
#include "net/packetbuf.h"
#include "net/linkaddr.h"
#include "net/netstack.h"
#include "net/mac/tsch/tsch.h"
#include "sys/energest.h"
#include "dev/cc2538-rf.h"
#include "dev/rfcore.h"
#include "dev/sys-ctrl.h"
#include "dev/udma.h"
#include "reg.h"
#include "lib/iq-seeder.h"

#include <string.h>
/*---------------------------------------------------------------------------*/
#define CHECKSUM_LEN 2

/* uDMA channel control persistent flags */
#define UDMA_TX_FLAGS (UDMA_CHCTL_ARBSIZE_128 | UDMA_CHCTL_XFERMODE_AUTO \
    | UDMA_CHCTL_SRCSIZE_8 | UDMA_CHCTL_DSTSIZE_8 \
    | UDMA_CHCTL_SRCINC_8 | UDMA_CHCTL_DSTINC_NONE)

#define UDMA_RX_FLAGS (UDMA_CHCTL_ARBSIZE_128 | UDMA_CHCTL_XFERMODE_AUTO \
    | UDMA_CHCTL_SRCSIZE_8 | UDMA_CHCTL_DSTSIZE_8 \
    | UDMA_CHCTL_SRCINC_NONE | UDMA_CHCTL_DSTINC_8)

/*
 * uDMA transfer threshold. DMA will only be used to read an incoming frame
 * if its size is above this threshold
 */
#define UDMA_RX_SIZE_THRESHOLD 3
/*---------------------------------------------------------------------------*/
/* Log configuration */
#include "sys/log.h"
#define LOG_MODULE "cc2538-rf"
#define LOG_LEVEL LOG_LEVEL_NONE
/*---------------------------------------------------------------------------*/
/* Bit Masks for the last byte in the RX FIFO */
#define CRC_BIT_MASK 0x80
#define LQI_BIT_MASK 0x7F
/* RSSI Offset */
#define RSSI_OFFSET    73
#define RSSI_INVALID -128

/* 192 usec off -> on interval (RX Callib -> SFD Wait). We wait a bit more */
#define ONOFF_TIME                    RTIMER_ARCH_SECOND / 3125
/*---------------------------------------------------------------------------*/
#ifdef CC2538_RF_CONF_AUTOACK
#define CC2538_RF_AUTOACK CC2538_RF_CONF_AUTOACK
#else
#define CC2538_RF_AUTOACK 1
#endif
/*---------------------------------------------------------------------------
 * MAC timer
 *---------------------------------------------------------------------------*/
/* Timer conversion */
#define RADIO_TO_RTIMER(X) ((uint32_t)((uint64_t)(X) * RTIMER_ARCH_SECOND / SYS_CTRL_32MHZ))

#define CLOCK_STABLE() do {															\
			while ( !(REG(SYS_CTRL_CLOCK_STA) & (SYS_CTRL_CLOCK_STA_XOSC_STB)));	\
		} while(0)
/*---------------------------------------------------------------------------*/
/* Do we perform a CCA before sending? Enabled by default. */
static uint8_t send_on_cca = 1;
static int8_t rssi;
static uint8_t crc_corr;
static uint_fast16_t frame_length;
static uint_fast16_t read_bytes;
static bool enter_rx_after_tx;
static radio_shr_callback_t shr_callback;
static radio_fifop_callback_t fifop_callback;
static radio_txdone_callback_t txdone_callback;
/*---------------------------------------------------------------------------*/
static struct {
  uint8_t ran_init:1;
  uint8_t in_rx_mode:1;
  uint8_t in_tx_mode:1;
  uint8_t in_poll_mode:1;
  uint8_t in_async_mode:1;
  uint8_t must_reset:1;
} rf_flags;
static uint8_t rf_channel = IEEE802154_DEFAULT_CHANNEL;

static int on(void);
static int off(void);
static radio_async_result_t async_append_to_sequence(uint8_t *appendix,
    uint_fast16_t appendix_len);
/*---------------------------------------------------------------------------*/
/* TX Power dBm lookup table. Values from SmartRF Studio v1.16.0 */
typedef struct output_config {
  radio_value_t power;
  uint8_t txpower_val;
} output_config_t;

static const output_config_t output_power[] = {
  {  7, 0xFF },
  {  5, 0xED },
  {  3, 0xD5 },
  {  1, 0xC5 },
  {  0, 0xB6 },
  { -1, 0xB0 },
  { -3, 0xA1 },
  { -5, 0x91 },
  { -7, 0x88 },
  { -9, 0x72 },
  {-11, 0x62 },
  {-13, 0x58 },
  {-15, 0x42 },
  {-24, 0x00 },
};

static radio_result_t get_value(radio_param_t param, radio_value_t *value);

#define OUTPUT_CONFIG_COUNT (sizeof(output_power) / sizeof(output_config_t))

/* Max and Min Output Power in dBm */
#define OUTPUT_POWER_MIN    (output_power[OUTPUT_CONFIG_COUNT - 1].power)
#define OUTPUT_POWER_MAX    (output_power[0].power)
/*---------------------------------------------------------------------------*/
/*
 * The maximum number of bytes this driver can accept from the MAC layer for
 * transmission or will deliver to the MAC layer after reception. Includes
 * the MAC header and payload, but not the FCS.
 */
#define MAX_PAYLOAD_LEN (CC2538_RF_MAX_PACKET_LEN - CHECKSUM_LEN)
/*---------------------------------------------------------------------------*/
PROCESS(cc2538_rf_process, "cc2538 RF driver");
/*---------------------------------------------------------------------------*/
static int
is_transmitting(void)
{
  return REG(RFCORE_XREG_FSMSTAT1) & RFCORE_XREG_FSMSTAT1_TX_ACTIVE;
}
/*---------------------------------------------------------------------------*/
static void
prepare_raw(const uint8_t *src, uint_fast16_t len)
{
  if(CC2538_RF_CONF_TX_USE_DMA) {
    /* Set the transfer source's end address */
    udma_set_channel_src(CC2538_RF_CONF_TX_DMA_CHAN,
        (uint32_t)(src) + (len - 1));
    /* Configure the control word */
    udma_set_channel_control_word(CC2538_RF_CONF_TX_DMA_CHAN,
        UDMA_TX_FLAGS | udma_xfer_size(len));
    /* Enable the RF TX uDMA channel */
    udma_channel_enable(CC2538_RF_CONF_TX_DMA_CHAN);
    /* Trigger the uDMA transfer */
    udma_channel_sw_request(CC2538_RF_CONF_TX_DMA_CHAN);
  } else {
    for(uint_fast16_t i = 0; i < len; i++) {
      REG(RFCORE_SFR_RFDATA) = src[i];
    }
  }
}
/*---------------------------------------------------------------------------*/
static void
read_raw(uint8_t *dst, uint_fast16_t len)
{
  /* Don't bother with uDMA for short frames (e.g. ACKs) */
  if(CC2538_RF_CONF_RX_USE_DMA && (len > UDMA_RX_SIZE_THRESHOLD)) {
    /* Set the transfer destination's end address */
    udma_set_channel_dst(CC2538_RF_CONF_RX_DMA_CHAN,
        (uint32_t)(dst) + len - 1);
    /* Configure the control word */
    udma_set_channel_control_word(CC2538_RF_CONF_RX_DMA_CHAN,
        UDMA_RX_FLAGS | udma_xfer_size(len));
    /* Enabled the RF RX uDMA channel */
    udma_channel_enable(CC2538_RF_CONF_RX_DMA_CHAN);
    /* Trigger the uDMA transfer */
    udma_channel_sw_request(CC2538_RF_CONF_RX_DMA_CHAN);
    /* Wait for the transfer to complete. */
    while(udma_channel_get_mode(CC2538_RF_CONF_RX_DMA_CHAN));
  } else {
    for(uint_fast16_t i = 0; i < len; ++i) {
      dst[i] = REG(RFCORE_SFR_RFDATA);
    }
  }
}
/*---------------------------------------------------------------------------*/
/**
 * \brief Get the current operating channel
 * \return Returns a value in [11,26] representing the current channel
 */
static uint8_t
get_channel()
{
  return rf_channel;
}
/*---------------------------------------------------------------------------*/
/**
 * \brief Set the current operating channel
 * \param channel The desired channel as a value in [11,26]
 */
static void
set_channel(uint8_t channel)
{
  uint8_t was_on = 0;

  LOG_INFO("Set Channel\n");

  /* Changes to FREQCTRL take effect after the next recalibration */

  /* If we are off, save state, otherwise switch off and save state */
  if((REG(RFCORE_XREG_FSMSTAT0) & RFCORE_XREG_FSMSTAT0_FSM_FFCTRL_STATE) != 0) {
    was_on = 1;
    off();
  }
  REG(RFCORE_XREG_FREQCTRL) = CC2538_RF_CHANNEL_MIN +
    (channel - CC2538_RF_CHANNEL_MIN) * CC2538_RF_CHANNEL_SPACING;

  /* switch radio back on only if radio was on before - otherwise will turn on radio foor sleepy nodes */
  if(was_on) {
    on();
  }

  rf_channel = channel;
}
/*---------------------------------------------------------------------------*/
static radio_value_t
get_pan_id(void)
{
  return (radio_value_t)(REG(RFCORE_FFSM_PAN_ID1) << 8 | REG(RFCORE_FFSM_PAN_ID0));
}
/*---------------------------------------------------------------------------*/
static void
set_pan_id(uint16_t pan)
{
  REG(RFCORE_FFSM_PAN_ID0) = pan & 0xFF;
  REG(RFCORE_FFSM_PAN_ID1) = pan >> 8;
}
/*---------------------------------------------------------------------------*/
static radio_value_t
get_short_addr(void)
{
  return (radio_value_t)(REG(RFCORE_FFSM_SHORT_ADDR1) << 8 | REG(RFCORE_FFSM_SHORT_ADDR0));
}
/*---------------------------------------------------------------------------*/
static void
set_short_addr(uint16_t addr)
{
  REG(RFCORE_FFSM_SHORT_ADDR0) = addr & 0xFF;
  REG(RFCORE_FFSM_SHORT_ADDR1) = addr >> 8;
}
/*---------------------------------------------------------------------------*/
/**
 * \brief Reads the current signal strength (RSSI)
 * \return The current RSSI in dBm
 *
 * This function reads the current RSSI on the currently configured
 * channel.
 */
static radio_value_t
get_rssi(void)
{
  int8_t rssi;
  uint8_t was_off = 0;

  /* If we are off, turn on first */
  if(!rf_flags.in_rx_mode) {
    was_off = 1;
    on();
  }

  /* Wait for a valid RSSI reading */
  do {
    rssi = REG(RFCORE_XREG_RSSI);
  } while(rssi == RSSI_INVALID);
  rssi -= RSSI_OFFSET;

  /* If we were off, turn back off */
  if(was_off) {
    off();
  }

  return rssi;
}
/*---------------------------------------------------------------------------*/
/**
 * \brief       Reads the current I/Q data of the received signal.
 * \param value The least significant bit (LSB) of the I coordinate and the LSB
 *              of the Q coordinate are concatenated and stored here.
 *
 * If not done already, this function first enables the RX mode and waits for
 * the RSSI_VALID bit to go high. Hence, this function should only be called
 * at start up or by the MAC protocol to avoid conflicts.
 */
static void
get_iq_lsbs(radio_value_t *value)
{
  uint8_t was_off = 0;

  /* If we are off, turn on first */
  if((REG(RFCORE_XREG_FSMSTAT0) & RFCORE_XREG_FSMSTAT0_FSM_FFCTRL_STATE) == 0) {
    was_off = 1;
    on();
  }

  /* Wait on RSSI_VALID */
  while((REG(RFCORE_XREG_RSSISTAT) & RFCORE_XREG_RSSISTAT_RSSI_VALID) == 0);

  /* Read I/Q LSBs */
  *value = REG(RFCORE_XREG_RFRND)
      & (RFCORE_XREG_RFRND_IRND | RFCORE_XREG_RFRND_QRND);

  /* If we were off, turn back off */
  if(was_off) {
    off();
  }
}
/*---------------------------------------------------------------------------*/
/* Returns the current CCA threshold in dBm */
static radio_value_t
get_cca_threshold(void)
{
  return (int8_t)(REG(RFCORE_XREG_CCACTRL0) & RFCORE_XREG_CCACTRL0_CCA_THR) - RSSI_OFFSET;
}
/*---------------------------------------------------------------------------*/
/* Sets the CCA threshold in dBm */
static void
set_cca_threshold(radio_value_t value)
{
  REG(RFCORE_XREG_CCACTRL0) = (value & 0xFF) + RSSI_OFFSET;
}
/*---------------------------------------------------------------------------*/
/* Returns the current TX power in dBm */
static radio_value_t
get_tx_power(void)
{
  int i;
  uint8_t reg_val = REG(RFCORE_XREG_TXPOWER) & 0xFF;

  /*
   * Find the TXPOWER value in the lookup table
   * If the value has been written with set_tx_power, we should be able to
   * find the exact value. However, in case the register has been written in
   * a different fashion, we return the immediately lower value of the lookup
   */
  for(i = 0; i < OUTPUT_CONFIG_COUNT; i++) {
    if(reg_val >= output_power[i].txpower_val) {
      return output_power[i].power;
    }
  }
  return OUTPUT_POWER_MIN;
}
/*---------------------------------------------------------------------------*/
/*
 * Set TX power to 'at least' power dBm
 * This works with a lookup table. If the value of 'power' does not exist in
 * the lookup table, TXPOWER will be set to the immediately higher available
 * value
 */
static void
set_tx_power(radio_value_t power)
{
  int i;

  for(i = OUTPUT_CONFIG_COUNT - 1; i >= 0; --i) {
    if(power <= output_power[i].power) {
      REG(RFCORE_XREG_TXPOWER) = output_power[i].txpower_val;
      return;
    }
  }
}
/*---------------------------------------------------------------------------*/
static void
set_frame_filtering(uint8_t enable)
{
  if(enable) {
    REG(RFCORE_XREG_FRMFILT0) |= RFCORE_XREG_FRMFILT0_FRAME_FILTER_EN;
  } else {
    REG(RFCORE_XREG_FRMFILT0) &= ~RFCORE_XREG_FRMFILT0_FRAME_FILTER_EN;
  }
}
/*---------------------------------------------------------------------------*/
static void
set_shr_search(int enable)
{
  if(enable) {
    REG(RFCORE_XREG_FRMCTRL0) &= ~RFCORE_XREG_FRMCTRL0_RX_MODE;
  } else {
    REG(RFCORE_XREG_FRMCTRL0) |= RFCORE_XREG_FRMCTRL0_RX_MODE;
  }
}
/*---------------------------------------------------------------------------*/
static void
mac_timer_init(void)
{
  CLOCK_STABLE();
  REG(RFCORE_SFR_MTCTRL) |= RFCORE_SFR_MTCTRL_SYNC;
  REG(RFCORE_SFR_MTCTRL) |= RFCORE_SFR_MTCTRL_RUN;
  while(!(REG(RFCORE_SFR_MTCTRL) & RFCORE_SFR_MTCTRL_STATE));
  REG(RFCORE_SFR_MTCTRL) &= ~RFCORE_SFR_MTCTRL_RUN;
  while(REG(RFCORE_SFR_MTCTRL) & RFCORE_SFR_MTCTRL_STATE);
  REG(RFCORE_SFR_MTCTRL) |= RFCORE_SFR_MTCTRL_SYNC;
  REG(RFCORE_SFR_MTCTRL) |= (RFCORE_SFR_MTCTRL_RUN);
  while(!(REG(RFCORE_SFR_MTCTRL) & RFCORE_SFR_MTCTRL_STATE));
}
/*---------------------------------------------------------------------------*/
static void
set_poll_mode(uint8_t enable)
{
  rf_flags.in_poll_mode = enable;

  if(enable) {
    mac_timer_init();
    REG(RFCORE_XREG_RFIRQM0) &= ~RFCORE_XREG_RFIRQM0_FIFOP; /* mask out FIFOP interrupt source */
    REG(RFCORE_SFR_RFIRQF0) &= ~RFCORE_SFR_RFIRQF0_FIFOP;   /* clear pending FIFOP interrupt */
    NVIC_DisableIRQ(RF_TX_RX_IRQn);                         /* disable RF interrupts */
  } else {
    REG(RFCORE_XREG_RFIRQM0) |= RFCORE_XREG_RFIRQM0_FIFOP;  /* enable FIFOP interrupt source */
    NVIC_EnableIRQ(RF_TX_RX_IRQn);                          /* enable RF interrupts */
  }
}
/*---------------------------------------------------------------------------*/
static void
set_send_on_cca(uint8_t enable)
{
  send_on_cca = enable;
}
/*---------------------------------------------------------------------------*/
static void
set_auto_ack(uint8_t enable)
{
  if(enable) {
    REG(RFCORE_XREG_FRMCTRL0) |= RFCORE_XREG_FRMCTRL0_AUTOACK;
  } else {
    REG(RFCORE_XREG_FRMCTRL0) &= ~RFCORE_XREG_FRMCTRL0_AUTOACK;
  }
}
/*---------------------------------------------------------------------------*/
static uint32_t
get_sfd_timestamp(void)
{
  uint64_t sfd, timer_val, buffer;

  REG(RFCORE_SFR_MTMSEL) = (REG(RFCORE_SFR_MTMSEL) & ~RFCORE_SFR_MTMSEL_MTMSEL) | 0x00000000;
  REG(RFCORE_SFR_MTCTRL) |= RFCORE_SFR_MTCTRL_LATCH_MODE;
  timer_val = REG(RFCORE_SFR_MTM0) & RFCORE_SFR_MTM0_MTM0;
  timer_val |= ((REG(RFCORE_SFR_MTM1) & RFCORE_SFR_MTM1_MTM1) << 8);
  REG(RFCORE_SFR_MTMSEL) = (REG(RFCORE_SFR_MTMSEL) & ~RFCORE_SFR_MTMSEL_MTMOVFSEL) | 0x00000000;
  timer_val |= ((REG(RFCORE_SFR_MTMOVF0) & RFCORE_SFR_MTMOVF0_MTMOVF0) << 16);
  timer_val |= ((REG(RFCORE_SFR_MTMOVF1) & RFCORE_SFR_MTMOVF1_MTMOVF1) << 24);
  buffer = REG(RFCORE_SFR_MTMOVF2) & RFCORE_SFR_MTMOVF2_MTMOVF2;
  timer_val |= (buffer << 32);

  REG(RFCORE_SFR_MTMSEL) = (REG(RFCORE_SFR_MTMSEL) & ~RFCORE_SFR_MTMSEL_MTMSEL) | 0x00000001;
  REG(RFCORE_SFR_MTCTRL) |= RFCORE_SFR_MTCTRL_LATCH_MODE;
  sfd = REG(RFCORE_SFR_MTM0) & RFCORE_SFR_MTM0_MTM0;
  sfd |= ((REG(RFCORE_SFR_MTM1) & RFCORE_SFR_MTM1_MTM1) << 8);
  REG(RFCORE_SFR_MTMSEL) = (REG(RFCORE_SFR_MTMSEL) & ~RFCORE_SFR_MTMSEL_MTMOVFSEL) | 0x00000010;
  sfd |= ((REG(RFCORE_SFR_MTMOVF0) & RFCORE_SFR_MTMOVF0_MTMOVF0) << 16);
  sfd |= ((REG(RFCORE_SFR_MTMOVF1) & RFCORE_SFR_MTMOVF1_MTMOVF1) << 24);
  buffer = REG(RFCORE_SFR_MTMOVF2) & RFCORE_SFR_MTMOVF2_MTMOVF2;
  sfd |= (buffer << 32);

  return RTIMER_NOW() - RADIO_TO_RTIMER(timer_val - sfd);
}
/*---------------------------------------------------------------------------*/
/* Enable or disable radio test mode emmiting modulated or unmodulated
 * (carrier) signal. See User's Guide pages 719 and 741.
 */
static uint32_t prev_FRMCTRL0, prev_MDMTEST1;
static uint8_t was_on;

static void
set_test_mode(uint8_t enable, uint8_t modulated)
{
  radio_value_t mode;
  get_value(RADIO_PARAM_POWER_MODE, &mode);

  if(enable) {
    if(mode == RADIO_POWER_MODE_CARRIER_ON) {
      return;
    }
    was_on = (mode == RADIO_POWER_MODE_ON);
    off();
    prev_FRMCTRL0 = REG(RFCORE_XREG_FRMCTRL0);
    /* This constantly transmits random data */
    REG(RFCORE_XREG_FRMCTRL0) = 0x00000042;
    if(!modulated) {
      prev_MDMTEST1 = REG(RFCORE_XREG_MDMTEST1);
      /* ...adding this we send an unmodulated carrier instead */
      REG(RFCORE_XREG_MDMTEST1) = 0x00000018;
    }
    CC2538_RF_CSP_ISTXON();
  } else {
    if(mode != RADIO_POWER_MODE_CARRIER_ON) {
      return;
    }
    CC2538_RF_CSP_ISRFOFF();
    REG(RFCORE_XREG_FRMCTRL0) = prev_FRMCTRL0;
    if(!modulated) {
      REG(RFCORE_XREG_MDMTEST1) = prev_MDMTEST1;
    }
    if(was_on) {
      on();
    }
  }
}
/*---------------------------------------------------------------------------*/
/* Netstack API radio driver functions */
/*---------------------------------------------------------------------------*/
static int
channel_clear(void)
{
  int cca;
  uint8_t was_off = 0;

  LOG_INFO("CCA\n");

  /* If we are off, turn on first */
  if((REG(RFCORE_XREG_FSMSTAT0) & RFCORE_XREG_FSMSTAT0_FSM_FFCTRL_STATE) == 0) {
    was_off = 1;
    on();
  }

  /* Wait on RSSI_VALID */
  while((REG(RFCORE_XREG_RSSISTAT) & RFCORE_XREG_RSSISTAT_RSSI_VALID) == 0);

  if(REG(RFCORE_XREG_FSMSTAT1) & RFCORE_XREG_FSMSTAT1_CCA) {
    cca = CC2538_RF_CCA_CLEAR;
  } else {
    cca = CC2538_RF_CCA_BUSY;
  }

  /* If we were off, turn back off */
  if(was_off) {
    off();
  }

  return cca;
}
/*---------------------------------------------------------------------------*/
static int
on(void)
{
  LOG_INFO("On\n");

  if(!rf_flags.in_rx_mode) {
    CC2538_RF_CSP_ISFLUSHRX();
    CC2538_RF_CSP_ISRXON();

    rf_flags.in_rx_mode = 1;
  }

  ENERGEST_ON(ENERGEST_TYPE_LISTEN);
  return 1;
}
/*---------------------------------------------------------------------------*/
static int
off(void)
{
  LOG_INFO("Off\n");

  /* Wait for ongoing TX to complete (e.g. this could be an outgoing ACK) */
  while(is_transmitting());

  if(!(REG(RFCORE_XREG_FSMSTAT1) & RFCORE_XREG_FSMSTAT1_FIFOP)) {
    CC2538_RF_CSP_ISFLUSHRX();
  }

  /* Don't turn off if we are off as this will trigger a Strobe Error */
  if(REG(RFCORE_XREG_RXENABLE) != 0) {
    CC2538_RF_CSP_ISRFOFF();
  }

  rf_flags.in_rx_mode = 0;

  ENERGEST_OFF(ENERGEST_TYPE_LISTEN);
  return 1;
}
/*---------------------------------------------------------------------------*/
static int
init(void)
{
  LOG_INFO("Init\n");

  if(rf_flags.ran_init) {
    return 0;
  }

  /* Enable clock for the RF Core while Running, in Sleep and Deep Sleep */
  REG(SYS_CTRL_RCGCRFC) = 1;
  REG(SYS_CTRL_SCGCRFC) = 1;
  REG(SYS_CTRL_DCGCRFC) = 1;

  REG(RFCORE_XREG_CCACTRL0) = CC2538_RF_CCA_THRES;

  /*
   * Changes from default values
   * See User Guide, section "Register Settings Update"
   */
  REG(RFCORE_XREG_TXFILTCFG) = 0x09;    /** TX anti-aliasing filter bandwidth */
  REG(RFCORE_XREG_AGCCTRL1) = 0x15;     /** AGC target value */
  REG(ANA_REGS_IVCTRL) = 0x0B;          /** Bias currents */
  REG(RFCORE_XREG_FSCAL1) = 0x01;       /** Tune frequency calibration */

  /*
   * Defaults:
   * Auto CRC; Append RSSI, CRC-OK and Corr. Val.; CRC calculation;
   * RX and TX modes with FIFOs
   */
  REG(RFCORE_XREG_FRMCTRL0) = RFCORE_XREG_FRMCTRL0_AUTOCRC;

#if CC2538_RF_AUTOACK
  REG(RFCORE_XREG_FRMCTRL0) |= RFCORE_XREG_FRMCTRL0_AUTOACK;
#endif

  /* Disable source address matching and autopend */
  REG(RFCORE_XREG_SRCMATCH) = 0;

  /* MAX FIFOP threshold */
  REG(RFCORE_XREG_FIFOPCTRL) = CC2538_RF_MAX_PACKET_LEN;

  /* Set TX Power */
  REG(RFCORE_XREG_TXPOWER) = CC2538_RF_TX_POWER;

  set_channel(rf_channel);

  /* Enable SHR search */
  set_shr_search(RADIO_SHR_SEARCH_EN);

  /* Acknowledge all RF Error interrupts */
  REG(RFCORE_XREG_RFERRM) = RFCORE_XREG_RFERRM_RFERRM;
  NVIC_EnableIRQ(RF_ERR_IRQn);

  if(CC2538_RF_CONF_TX_USE_DMA) {
    /* Disable peripheral triggers for the channel */
    udma_channel_mask_set(CC2538_RF_CONF_TX_DMA_CHAN);

    /*
     * Set the channel's DST. SRC can not be set yet since it will change for
     * each transfer
     */
    udma_set_channel_dst(CC2538_RF_CONF_TX_DMA_CHAN, RFCORE_SFR_RFDATA);
  }

  if(CC2538_RF_CONF_RX_USE_DMA) {
    /* Disable peripheral triggers for the channel */
    udma_channel_mask_set(CC2538_RF_CONF_RX_DMA_CHAN);

    /*
     * Set the channel's SRC. DST can not be set yet since it will change for
     * each transfer
     */
    udma_set_channel_src(CC2538_RF_CONF_RX_DMA_CHAN, RFCORE_SFR_RFDATA);
  }

  set_poll_mode(rf_flags.in_poll_mode);

#if CSPRNG_ENABLED
  iq_seeder_seed();
#endif /* CSPRNG_ENABLED */

  process_start(&cc2538_rf_process, NULL);

  rf_flags.ran_init = 1;

  return 1;
}
/*---------------------------------------------------------------------------*/
static int
prepare(const void *payload, unsigned short payload_len)
{
  if(payload_len > MAX_PAYLOAD_LEN) {
    return RADIO_TX_ERR;
  }

  LOG_INFO("Prepare 0x%02x bytes\n", payload_len + CHECKSUM_LEN);

  /*
   * When we transmit in very quick bursts, make sure previous transmission
   * is not still in progress before re-writing to the TX FIFO
   */
  while(is_transmitting());

  if(!rf_flags.in_rx_mode) {
    on();
  }

  CC2538_RF_CSP_ISFLUSHTX();

  /* Send the phy length byte first */
  REG(RFCORE_SFR_RFDATA) = payload_len + CHECKSUM_LEN;

  prepare_raw(payload, payload_len);

  return 0;
}
/*---------------------------------------------------------------------------*/
static int
transmit(unsigned short transmit_len)
{
  uint8_t counter;
  int ret = RADIO_TX_ERR;
  rtimer_clock_t t0;
  uint8_t was_off = 0;

  LOG_INFO("Transmit\n");

  if(transmit_len > MAX_PAYLOAD_LEN) {
    return RADIO_TX_ERR;
  }

  if(!rf_flags.in_rx_mode) {
    t0 = RTIMER_NOW();
    on();
    was_off = 1;
    while(RTIMER_CLOCK_LT(RTIMER_NOW(), t0 + ONOFF_TIME));
  }

  if(send_on_cca) {
    if(channel_clear() == CC2538_RF_CCA_BUSY) {
      return RADIO_TX_COLLISION;
    }
  }

  /*
   * prepare() double checked that TX_ACTIVE is low. If SFD is high we are
   * receiving. Abort transmission and bail out with RADIO_TX_COLLISION
   */
  if(REG(RFCORE_XREG_FSMSTAT1) & RFCORE_XREG_FSMSTAT1_SFD) {
    return RADIO_TX_COLLISION;
  }

  /* Start the transmission */
  ENERGEST_SWITCH(ENERGEST_TYPE_LISTEN, ENERGEST_TYPE_TRANSMIT);

  CC2538_RF_CSP_ISTXON();

  counter = 0;
  while(!((is_transmitting()))
        && (counter++ < 3)) {
    clock_delay_usec(6);
  }

  if(!(is_transmitting())) {
    LOG_ERR("TX never active.\n");
    CC2538_RF_CSP_ISFLUSHTX();
    ret = RADIO_TX_ERR;
  } else {
    /* Wait for the transmission to finish */
    while(is_transmitting());
    ret = RADIO_TX_OK;
  }
  ENERGEST_SWITCH(ENERGEST_TYPE_TRANSMIT, ENERGEST_TYPE_LISTEN);

  if(was_off) {
    off();
  }

  return ret;
}
/*---------------------------------------------------------------------------*/
static int
send(const void *payload, unsigned short payload_len)
{
  prepare(payload, payload_len);
  return transmit(payload_len);
}
/*---------------------------------------------------------------------------*/
static int
read(void *buf, unsigned short bufsize)
{
  uint8_t len;

  LOG_INFO("Read\n");

  if((REG(RFCORE_XREG_FSMSTAT1) & RFCORE_XREG_FSMSTAT1_FIFOP) == 0) {
    return 0;
  }

  /* Check the length */
  len = REG(RFCORE_SFR_RFDATA);

  /* Check for validity */
  if(len > CC2538_RF_MAX_PACKET_LEN) {
    /* Oops, we must be out of sync. */
    LOG_ERR("RF: bad sync\n");

    CC2538_RF_CSP_ISFLUSHRX();
    return 0;
  }

  if(len <= CC2538_RF_MIN_PACKET_LEN) {
    LOG_ERR("RF: too short\n");

    CC2538_RF_CSP_ISFLUSHRX();
    return 0;
  }

  if(len - CHECKSUM_LEN > bufsize) {
    LOG_ERR("RF: too long\n");

    CC2538_RF_CSP_ISFLUSHRX();
    return 0;
  }

  /* If we reach here, chances are the FIFO is holding a valid frame */
  len -= CHECKSUM_LEN;

  read_raw(buf, len);

  /* Read the RSSI and CRC/Corr bytes */
  rssi = ((int8_t)REG(RFCORE_SFR_RFDATA)) - RSSI_OFFSET;
  crc_corr = REG(RFCORE_SFR_RFDATA);

  /* MS bit CRC OK/Not OK, 7 LS Bits, Correlation value */
  if(crc_corr & CRC_BIT_MASK) {
    packetbuf_set_attr(PACKETBUF_ATTR_RSSI, rssi);
    packetbuf_set_attr(PACKETBUF_ATTR_LINK_QUALITY, crc_corr & LQI_BIT_MASK);
  } else {
    LOG_ERR("Bad CRC\n");
    CC2538_RF_CSP_ISFLUSHRX();
    return 0;
  }

  if(!rf_flags.in_poll_mode) {
    /* If FIFOP==1 and FIFO==0 then we had a FIFO overflow at some point. */
    if(REG(RFCORE_XREG_FSMSTAT1) & RFCORE_XREG_FSMSTAT1_FIFOP) {
      if(REG(RFCORE_XREG_FSMSTAT1) & RFCORE_XREG_FSMSTAT1_FIFO) {
        process_poll(&cc2538_rf_process);
      } else {
        CC2538_RF_CSP_ISFLUSHRX();
      }
    }
  }

  return len;
}
/*---------------------------------------------------------------------------*/
static int
receiving_packet(void)
{
  LOG_INFO("Receiving\n");

  /*
   * SFD high while transmitting and receiving.
   * TX_ACTIVE high only when transmitting
   *
   * FSMSTAT1 & (TX_ACTIVE | SFD) == SFD <=> receiving
   */
  return (REG(RFCORE_XREG_FSMSTAT1)
          & (RFCORE_XREG_FSMSTAT1_TX_ACTIVE | RFCORE_XREG_FSMSTAT1_SFD))
         == RFCORE_XREG_FSMSTAT1_SFD;
}
/*---------------------------------------------------------------------------*/
static int
pending_packet(void)
{
  LOG_INFO("Pending\n");

  return REG(RFCORE_XREG_FSMSTAT1) & RFCORE_XREG_FSMSTAT1_FIFOP;
}
/*---------------------------------------------------------------------------*/
static radio_result_t
get_value(radio_param_t param, radio_value_t *value)
{
  if(!value) {
    return RADIO_RESULT_INVALID_VALUE;
  }

  switch(param) {
  case RADIO_PARAM_POWER_MODE:
    if((REG(RFCORE_XREG_RXENABLE) & RFCORE_XREG_RXENABLE_RXENMASK) == 0) {
      *value = RADIO_POWER_MODE_OFF;
    } else {
      *value = (REG(RFCORE_XREG_FRMCTRL0) & RFCORE_XREG_FRMCTRL0_TX_MODE) == 0
        ? RADIO_POWER_MODE_ON : RADIO_POWER_MODE_CARRIER_ON;
    }
    return RADIO_RESULT_OK;
  case RADIO_PARAM_CHANNEL:
    *value = (radio_value_t)get_channel();
    return RADIO_RESULT_OK;
  case RADIO_PARAM_PAN_ID:
    *value = get_pan_id();
    return RADIO_RESULT_OK;
  case RADIO_PARAM_16BIT_ADDR:
    *value = get_short_addr();
    return RADIO_RESULT_OK;
  case RADIO_PARAM_RX_MODE:
    *value = 0;
    if(REG(RFCORE_XREG_FRMFILT0) & RFCORE_XREG_FRMFILT0_FRAME_FILTER_EN) {
      *value |= RADIO_RX_MODE_ADDRESS_FILTER;
    }
    if(REG(RFCORE_XREG_FRMCTRL0) & RFCORE_XREG_FRMCTRL0_AUTOACK) {
      *value |= RADIO_RX_MODE_AUTOACK;
    }
    if(rf_flags.in_poll_mode) {
      *value |= RADIO_RX_MODE_POLL_MODE;
    }
    return RADIO_RESULT_OK;
  case RADIO_PARAM_TX_MODE:
    *value = 0;
    if(send_on_cca) {
      *value |= RADIO_TX_MODE_SEND_ON_CCA;
    }
    return RADIO_RESULT_OK;
  case RADIO_PARAM_TXPOWER:
    *value = get_tx_power();
    return RADIO_RESULT_OK;
  case RADIO_PARAM_CCA_THRESHOLD:
    *value = get_cca_threshold();
    return RADIO_RESULT_OK;
  case RADIO_PARAM_RSSI:
    *value = get_rssi();
    return RADIO_RESULT_OK;
  case RADIO_PARAM_LAST_RSSI:
    *value = rssi;
    return RADIO_RESULT_OK;
  case RADIO_PARAM_LAST_LINK_QUALITY:
    *value = crc_corr & LQI_BIT_MASK;
    return RADIO_RESULT_OK;
  case RADIO_PARAM_IQ_LSBS:
    get_iq_lsbs(value);
    return RADIO_RESULT_OK;
  case RADIO_CONST_CHANNEL_MIN:
    *value = CC2538_RF_CHANNEL_MIN;
    return RADIO_RESULT_OK;
  case RADIO_CONST_CHANNEL_MAX:
    *value = CC2538_RF_CHANNEL_MAX;
    return RADIO_RESULT_OK;
  case RADIO_CONST_TXPOWER_MIN:
    *value = OUTPUT_POWER_MIN;
    return RADIO_RESULT_OK;
  case RADIO_CONST_TXPOWER_MAX:
    *value = OUTPUT_POWER_MAX;
    return RADIO_RESULT_OK;
  case RADIO_CONST_PHY_OVERHEAD:
    *value = (radio_value_t)3; /* 1 len byte, 2 bytes CRC */
    return RADIO_RESULT_OK;
  case RADIO_CONST_BYTE_AIR_TIME:
    *value = (radio_value_t)32; /* 250kbps data rate. One byte = 32us.*/
    return RADIO_RESULT_OK;
  case RADIO_CONST_DELAY_BEFORE_TX:
    *value = (radio_value_t)CC2538_DELAY_BEFORE_TX;
    return RADIO_RESULT_OK;
  case RADIO_CONST_DELAY_BEFORE_RX:
    *value = (radio_value_t)CC2538_DELAY_BEFORE_RX;
    return RADIO_RESULT_OK;
  case RADIO_CONST_DELAY_BEFORE_DETECT:
    *value = (radio_value_t)CC2538_DELAY_BEFORE_DETECT;
    return RADIO_RESULT_OK;
  case RADIO_CONST_MAX_PAYLOAD_LEN:
    *value = (radio_value_t)MAX_PAYLOAD_LEN;
    return RADIO_RESULT_OK;
  default:
    return RADIO_RESULT_NOT_SUPPORTED;
  }
}
/*---------------------------------------------------------------------------*/
static radio_result_t
set_value(radio_param_t param, radio_value_t value)
{
  switch(param) {
  case RADIO_PARAM_POWER_MODE:
    if(value == RADIO_POWER_MODE_ON) {
      on();
      return RADIO_RESULT_OK;
    }
    if(value == RADIO_POWER_MODE_OFF) {
      off();
      return RADIO_RESULT_OK;
    }
    if(value == RADIO_POWER_MODE_CARRIER_ON ||
       value == RADIO_POWER_MODE_CARRIER_OFF) {
      set_test_mode((value == RADIO_POWER_MODE_CARRIER_ON), 0);
      return RADIO_RESULT_OK;
    }
    return RADIO_RESULT_INVALID_VALUE;
  case RADIO_PARAM_CHANNEL:
    if(value < CC2538_RF_CHANNEL_MIN ||
       value > CC2538_RF_CHANNEL_MAX) {
      return RADIO_RESULT_INVALID_VALUE;
    }
    set_channel(value);
    return RADIO_RESULT_OK;
  case RADIO_PARAM_PAN_ID:
    set_pan_id(value & 0xffff);
    return RADIO_RESULT_OK;
  case RADIO_PARAM_16BIT_ADDR:
    set_short_addr(value & 0xffff);
    return RADIO_RESULT_OK;
  case RADIO_PARAM_RX_MODE:
    if(value & ~(RADIO_RX_MODE_ADDRESS_FILTER |
                 RADIO_RX_MODE_AUTOACK |
                 RADIO_RX_MODE_POLL_MODE)) {
      return RADIO_RESULT_INVALID_VALUE;
    }

    set_frame_filtering((value & RADIO_RX_MODE_ADDRESS_FILTER) != 0);
    set_auto_ack((value & RADIO_RX_MODE_AUTOACK) != 0);
    set_poll_mode((value & RADIO_RX_MODE_POLL_MODE) != 0);

    return RADIO_RESULT_OK;
  case RADIO_PARAM_TX_MODE:
    if(value & ~(RADIO_TX_MODE_SEND_ON_CCA)) {
      return RADIO_RESULT_INVALID_VALUE;
    }
    set_send_on_cca((value & RADIO_TX_MODE_SEND_ON_CCA) != 0);
    return RADIO_RESULT_OK;
  case RADIO_PARAM_TXPOWER:
    if(value < OUTPUT_POWER_MIN || value > OUTPUT_POWER_MAX) {
      return RADIO_RESULT_INVALID_VALUE;
    }

    set_tx_power(value);
    return RADIO_RESULT_OK;
  case RADIO_PARAM_CCA_THRESHOLD:
    set_cca_threshold(value);
    return RADIO_RESULT_OK;
  case RADIO_PARAM_SHR_SEARCH:
    if((value != RADIO_SHR_SEARCH_EN) && (value != RADIO_SHR_SEARCH_DIS)) {
      return RADIO_RESULT_INVALID_VALUE;
    }
    set_shr_search(value);
    return RADIO_RESULT_OK;
  default:
    return RADIO_RESULT_NOT_SUPPORTED;
  }
}
/*---------------------------------------------------------------------------*/
static radio_result_t
get_object(radio_param_t param, void *dest, size_t size)
{
  uint8_t *target;
  int i;

  if(param == RADIO_PARAM_64BIT_ADDR) {
    if(size != 8 || !dest) {
      return RADIO_RESULT_INVALID_VALUE;
    }

    target = dest;
    for(i = 0; i < 8; i++) {
      target[i] = ((uint32_t *)RFCORE_FFSM_EXT_ADDR0)[7 - i] & 0xFF;
    }

    return RADIO_RESULT_OK;
  }

  if(param == RADIO_PARAM_LAST_PACKET_TIMESTAMP) {
    if(size != sizeof(rtimer_clock_t) || !dest) {
      return RADIO_RESULT_INVALID_VALUE;
    }
    *(rtimer_clock_t *)dest = get_sfd_timestamp();
    return RADIO_RESULT_OK;
  }

#if MAC_CONF_WITH_TSCH
  if(param == RADIO_CONST_TSCH_TIMING) {
    if(size != sizeof(uint16_t *) || !dest) {
      return RADIO_RESULT_INVALID_VALUE;
    }
    /* Assigned value: a pointer to the TSCH timing in usec */
    *(const uint16_t **)dest = tsch_timeslot_timing_us_10000;
    return RADIO_RESULT_OK;
  }
#endif /* MAC_CONF_WITH_TSCH */

  return RADIO_RESULT_NOT_SUPPORTED;
}
/*---------------------------------------------------------------------------*/
static radio_result_t
set_object(radio_param_t param, const void *src, size_t size)
{
  int i;

  if(param == RADIO_PARAM_64BIT_ADDR) {
    if(size != 8 || !src) {
      return RADIO_RESULT_INVALID_VALUE;
    }

    for(i = 0; i < 8; i++) {
      ((uint32_t *)RFCORE_FFSM_EXT_ADDR0)[i] = ((uint8_t *)src)[7 - i];
    }

    return RADIO_RESULT_OK;
  }
  return RADIO_RESULT_NOT_SUPPORTED;
}
/*---------------------------------------------------------------------------*/
static radio_async_result_t
async_enter(void)
{
  rf_flags.in_async_mode = 1;

  /* Disable disabling of SFD detection after frame reception */
  REG(RFCORE_XREG_FSMCTRL) |= RFCORE_XREG_FSMCTRL_RX2RX_TIME_OFF;

  /* Raise the number of zero symbols needed for SHR detection */
  REG(RFCORE_XREG_MDMCTRL0) |= 3 << 6;

  /* Disable frame filtering */
  REG(RFCORE_XREG_FRMFILT0) &= ~RFCORE_XREG_FRMFILT0_FRAME_FILTER_EN;

  /* Disable AUTOCRC */
  REG(RFCORE_XREG_FRMCTRL0) &= ~RFCORE_XREG_FRMCTRL0_AUTOCRC;

  /* Disable AUTOACK */
  REG(RFCORE_XREG_FRMCTRL0) &= ~RFCORE_XREG_FRMCTRL0_AUTOACK;

  /* Configure interrupts */
  REG(RFCORE_XREG_RFIRQM0) = 0;
  REG(RFCORE_XREG_RFIRQM1) = RFCORE_XREG_RFIRQM1_TXDONE;
  NVIC_EnableIRQ(RF_TX_RX_IRQn);
  REG(RFCORE_XREG_RFERRM) = 0;
  NVIC_DisableIRQ(RF_ERR_IRQn);
  return RADIO_ASYNC_OK;
}
/*---------------------------------------------------------------------------*/
static radio_async_result_t
async_prepare(uint8_t *payload, uint_fast16_t payload_len)
{
  if(payload_len > CC2538_RF_MAX_PACKET_LEN) {
    return RADIO_ASYNC_INVALID_PARAMETER;
  }
  CC2538_RF_CSP_ISFLUSHTX();
  REG(RFCORE_XREG_FRMCTRL0) &= ~RFCORE_XREG_FRMCTRL0_TX_MODE_LOOP;
  REG(RFCORE_SFR_RFDATA) = payload_len;
  prepare_raw(payload, payload_len);
  return RADIO_ASYNC_OK;
}
/*---------------------------------------------------------------------------*/
static radio_async_result_t
async_reprepare(uint_fast16_t offset, uint8_t *patch, uint_fast16_t patch_len)
{
  if((offset + patch_len) > CC2538_RF_MAX_PACKET_LEN) {
    return RADIO_ASYNC_INVALID_PARAMETER;
  }
  for(uint_fast16_t i = 0; i < patch_len; i++) {
    REG(RFCORE_FFSM_TX_FIFO + 4 * (offset + RADIO_HEADER_LEN + i)) = patch[i];
  }
  return RADIO_ASYNC_OK;
}
/*---------------------------------------------------------------------------*/
static radio_async_result_t
async_transmit(bool shall_enter_rx_after_tx)
{
  if(rf_flags.in_tx_mode) {
    LOG_WARN("already transmitting\n");
    return RADIO_ASYNC_REDUNDANT_CALL;
  }
  rf_flags.in_rx_mode = 0;
  rf_flags.in_tx_mode = 1;

  enter_rx_after_tx = shall_enter_rx_after_tx;
  CC2538_RF_CSP_ISTXON();
  ENERGEST_SWITCH(ENERGEST_TYPE_LISTEN, ENERGEST_TYPE_TRANSMIT);
  return RADIO_ASYNC_OK;
}
/*---------------------------------------------------------------------------*/
static radio_async_result_t
async_on(void)
{
  if(rf_flags.in_rx_mode) {
    LOG_WARN("already receiving\n");
    return RADIO_ASYNC_REDUNDANT_CALL;
  }
  rf_flags.in_rx_mode = 1;

  CC2538_RF_CSP_ISRXON();
  CC2538_RF_CSP_ISFLUSHRX();
  ENERGEST_ON(ENERGEST_TYPE_LISTEN);
  return RADIO_ASYNC_OK;
}
/*---------------------------------------------------------------------------*/
static radio_async_result_t
async_off(void)
{
  if(!rf_flags.in_rx_mode && !rf_flags.in_tx_mode) {
    LOG_WARN("already off\n");
    return RADIO_ASYNC_REDUNDANT_CALL;
  }
  rf_flags.in_rx_mode = 0;
  rf_flags.in_tx_mode = 0;

  CC2538_RF_CSP_ISRFOFF();
  ENERGEST_OFF(ENERGEST_TYPE_TRANSMIT);
  ENERGEST_OFF(ENERGEST_TYPE_LISTEN);
  return RADIO_ASYNC_OK;
}
/*---------------------------------------------------------------------------*/
static void
async_set_shr_callback(radio_shr_callback_t cb)
{
  shr_callback = cb;
  if(shr_callback) {
    REG(RFCORE_XREG_RFIRQM0) |= RFCORE_XREG_RFIRQM0_SFD;
  } else {
    REG(RFCORE_XREG_RFIRQM0) &= ~RFCORE_XREG_RFIRQM0_SFD;
  }
}
/*---------------------------------------------------------------------------*/
static void
async_set_fifop_callback(radio_fifop_callback_t cb, uint_fast16_t threshold)
{
  fifop_callback = cb;
  if(threshold > CC2538_RF_MAX_PACKET_LEN) {
    LOG_WARN("truncating FIFOP threshold\n");
    threshold = CC2538_RF_MAX_PACKET_LEN;
  }
  if(cb || (threshold == CC2538_RF_MAX_PACKET_LEN)) {
    REG(RFCORE_XREG_FIFOPCTRL) = threshold;
    REG(RFCORE_XREG_RFIRQM0) |= RFCORE_XREG_RFIRQM0_FIFOP;
  } else {
    REG(RFCORE_XREG_RFIRQM0) &= ~RFCORE_XREG_RFIRQM0_FIFOP;
  }
}
/*---------------------------------------------------------------------------*/
static void
async_set_txdone_callback(radio_txdone_callback_t cb)
{
  txdone_callback = cb;
}
/*---------------------------------------------------------------------------*/
static uint_fast16_t
async_read_phy_header(void)
{
  while(!REG(RFCORE_XREG_RXFIFOCNT));
  frame_length = REG(RFCORE_SFR_RFDATA) & 0x7F /* ignore reserved bits */;
  read_bytes = 0;
  return frame_length;
}
/*---------------------------------------------------------------------------*/
static radio_async_result_t
async_read_payload(uint8_t *buf, uint_fast16_t bytes)
{
  if(frame_length < bytes) {
    return RADIO_ASYNC_INVALID_PARAMETER;
  }
  while(REG(RFCORE_XREG_RXFIFOCNT) < bytes);
  read_raw(buf, bytes);
  read_bytes += bytes;
  return RADIO_ASYNC_OK;
}
/*---------------------------------------------------------------------------*/
static uint_fast16_t
async_read_payload_bytes(void)
{
  return read_bytes;
}
/*---------------------------------------------------------------------------*/
static radio_async_result_t
async_prepare_sequence(uint8_t *sequence, uint_fast16_t sequence_len)
{
  if(sequence_len > RADIO_MAX_SEQUENCE_LEN) {
    return RADIO_ASYNC_INVALID_PARAMETER;
  }
  CC2538_RF_CSP_ISFLUSHTX();
  REG(RFCORE_XREG_FRMCTRL0) |= RFCORE_XREG_FRMCTRL0_TX_MODE_LOOP;
  async_append_to_sequence(
      sequence + RADIO_SHR_LEN /* the first SHR is transmitted automatically */,
      sequence_len - RADIO_SHR_LEN);
  return RADIO_ASYNC_OK;
}
/*---------------------------------------------------------------------------*/
static radio_async_result_t
async_append_to_sequence(uint8_t *appendix, uint_fast16_t appendix_len)
{
  if(appendix_len > RADIO_MAX_SEQUENCE_LEN) {
    return RADIO_ASYNC_INVALID_PARAMETER;
  }
  prepare_raw(appendix, appendix_len);
  return RADIO_ASYNC_OK;
}
/*---------------------------------------------------------------------------*/
static radio_async_result_t
async_transmit_sequence(void)
{
  return async_transmit(false);
}
/*---------------------------------------------------------------------------*/
static radio_async_result_t
async_finish_sequence(void)
{
  if(!is_transmitting()) {
    LOG_WARN("am not looping\n");
    return RADIO_ASYNC_ERROR;
  }

  uint_fast8_t end_pos = REG(RFCORE_XREG_TXLAST_PTR) & 0x7F;
  end_pos++;
  while((REG(RFCORE_XREG_TXFIRST_PTR) & 0x7F) != end_pos);
  while((REG(RFCORE_XREG_TXFIRST_PTR) & 0x7F) == end_pos);
  async_off();
  return RADIO_ASYNC_OK;
}
/*---------------------------------------------------------------------------*/
const struct radio_driver cc2538_rf_driver = {
  init,
  prepare,
  transmit,
  send,
  read,
  channel_clear,
  receiving_packet,
  pending_packet,
  on,
  off,
  get_value,
  set_value,
  get_object,
  set_object,
  async_enter,
  async_prepare,
  async_reprepare,
  async_transmit,
  async_on,
  async_off,
  async_set_shr_callback,
  async_set_fifop_callback,
  async_set_txdone_callback,
  async_read_phy_header,
  async_read_payload,
  async_read_payload_bytes,
  async_prepare_sequence,
  async_append_to_sequence,
  async_transmit_sequence,
  async_finish_sequence
};
/*---------------------------------------------------------------------------*/
/**
 * \brief Implementation of the cc2538 RF driver process
 *
 *        This process is started by init(). It simply sits there waiting for
 *        an event. Upon frame reception, the RX ISR will poll this process.
 *        Subsequently, the contiki core will generate an event which will
 *        call this process so that the received frame can be picked up from
 *        the RF RX FIFO
 *
 */
PROCESS_THREAD(cc2538_rf_process, ev, data)
{
  int len;
  PROCESS_BEGIN();

  while(1) {
    PROCESS_YIELD_UNTIL(ev == PROCESS_EVENT_POLL);

    if(!rf_flags.in_poll_mode) {
      packetbuf_clear();
      len = read(packetbuf_dataptr(), PACKETBUF_SIZE);

      if(len > 0) {
        packetbuf_set_datalen(len);

        NETSTACK_MAC.input();
      }
    }

    /* If we were polled due to an RF error, reset the transceiver */
    if(rf_flags.must_reset) {
      uint8_t was_on;
      memset(&rf_flags, 0, sizeof(rf_flags));

      /* save state so we know if to switch on again after re-init */
      if((REG(RFCORE_XREG_FSMSTAT0) & RFCORE_XREG_FSMSTAT0_FSM_FFCTRL_STATE) == 0) {
        was_on = 0;
      } else {
        was_on = 1;
      }
      off();
      init();
      if(was_on) {
        /* switch back on */
        on();
      }
    }
  }

  PROCESS_END();
}
/*---------------------------------------------------------------------------*/
/**
 * \brief The cc2538 RF RX/TX ISR
 *
 *        This is the interrupt service routine for all RF interrupts relating
 *        to RX and TX. Error conditions are handled by cc2538_rf_err_isr().
 *        Currently, we only acknowledge the FIFOP interrupt source.
 */
void
cc2538_rf_rx_tx_isr(void)
{
  if(rf_flags.in_async_mode) {
    if(REG(RFCORE_SFR_RFIRQF0) & RFCORE_SFR_RFIRQF0_SFD) {
      NVIC_ClearPendingIRQ(RF_TX_RX_IRQn);
      REG(RFCORE_SFR_RFIRQF0) &= ~RFCORE_SFR_RFIRQF0_SFD;
      if(shr_callback) {
        shr_callback();
      }
    }
    if(REG(RFCORE_SFR_RFIRQF0) & RFCORE_SFR_RFIRQF0_FIFOP) {
      NVIC_ClearPendingIRQ(RF_TX_RX_IRQn);
      REG(RFCORE_SFR_RFIRQF0) &= ~RFCORE_SFR_RFIRQF0_FIFOP;
      if(fifop_callback) {
        fifop_callback();
      }
    }
    if(REG(RFCORE_SFR_RFIRQF1) & RFCORE_SFR_RFIRQF1_TXDONE) {
      NVIC_ClearPendingIRQ(RF_TX_RX_IRQn);
      REG(RFCORE_SFR_RFIRQF1) &= ~RFCORE_SFR_RFIRQF1_TXDONE;
      if(enter_rx_after_tx) {
        CC2538_RF_CSP_ISFLUSHRX();
        rf_flags.in_tx_mode = 0;
        rf_flags.in_rx_mode = 1;
        ENERGEST_SWITCH(ENERGEST_TYPE_TRANSMIT, ENERGEST_TYPE_LISTEN);
      } else {
        async_off();
      }
      if(txdone_callback) {
        txdone_callback();
      }
    }
  } else {
    if(!rf_flags.in_poll_mode) {
      process_poll(&cc2538_rf_process);
    }

    /* We only acknowledge FIFOP so we can safely wipe out the entire SFR */
    REG(RFCORE_SFR_RFIRQF0) = 0;
  }
}
/*---------------------------------------------------------------------------*/
/**
 * \brief The cc2538 RF Error ISR
 *
 *        This is the interrupt service routine for all RF errors. We
 *        acknowledge every error type and instead of trying to be smart and
 *        act differently depending on error condition, we simply reset the
 *        transceiver. RX FIFO overflow is an exception, we ignore this error
 *        since read() handles it anyway.
 *
 *        However, we don't want to reset within this ISR. If the error occurs
 *        while we are reading a frame out of the FIFO, trashing the FIFO in
 *        the middle of read(), would result in further errors (RX underflows).
 *
 *        Instead, we set a flag and poll the driver process. The process will
 *        reset the transceiver without any undesirable consequences.
 */
void
cc2538_rf_err_isr(void)
{
  LOG_ERR("Error 0x%08lx occurred\n", REG(RFCORE_SFR_RFERRF));

  /* If the error is not an RX FIFO overflow, set a flag */
  if(REG(RFCORE_SFR_RFERRF) != RFCORE_SFR_RFERRF_RXOVERF) {
    rf_flags.must_reset = 1;
  }

  REG(RFCORE_SFR_RFERRF) = 0;

  process_poll(&cc2538_rf_process);
}
/*---------------------------------------------------------------------------*/

/** @} */
