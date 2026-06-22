/*
 * Copyright (c) 2024, RISE Research Institutes of Sweden
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
 * \file
 *         Serial Radio - Main Application Entry Point
 * \author
 *         Joakim Eriksson <joakim.eriksson@ri.se>
 *
 * This application provides a serial interface to control the radio
 * using SLIP framing, CBOR encoding, and CRC16 integrity checking.
 *
 * Supported commands:
 * - PING: Test connectivity, returns version info
 * - GET_PARAM: Read radio parameters (channel, TX power, RSSI, etc.)
 * - SET_PARAM: Set radio parameters
 * - TX_RAW_FRAME: Transmit a raw 802.15.4 frame
 * - RSSI_SCAN_START/STOP: Channel scanning with RSSI measurements
 * - RX_ON/OFF: Enable/disable radio receiver
 */

#include "contiki.h"
#include "serial-radio.h"
#include "sys/log.h"

#include <stdio.h>

#define LOG_MODULE "Main"
#define LOG_LEVEL LOG_LEVEL_INFO

/*---------------------------------------------------------------------------*/
/* Main process */
/*---------------------------------------------------------------------------*/

PROCESS(main_process, "Serial Radio Main");
AUTOSTART_PROCESSES(&main_process, &serial_radio_process);

/*---------------------------------------------------------------------------*/
PROCESS_THREAD(main_process, ev, data)
{
  PROCESS_BEGIN();

  LOG_INFO("=================================\n");
  LOG_INFO("Serial Radio Control Interface\n");
  LOG_INFO("=================================\n");
  LOG_INFO("Platform: " CONTIKI_TARGET_STRING "\n");

  /* The serial_radio_process handles everything */

  while(1) {
    PROCESS_WAIT_EVENT();
  }

  PROCESS_END();
}
/*---------------------------------------------------------------------------*/
