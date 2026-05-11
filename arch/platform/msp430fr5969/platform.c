/*
 * Copyright (c) 2026, RISE Research Institutes of Sweden AB
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
 */

/**
 * \file
 *         Platform initialization for MSP-EXP430FR5969 LaunchPad
 */

#include <stdio.h>
#include <string.h>
#include "contiki.h"
#include "sys/energest.h"
#include "dev/leds.h"
#include "dev/serial-line.h"
#include "dev/uart0.h"
#include "dev/watchdog.h"
#include "sys/node-id.h"

extern int msp430_dco_required;

/*---------------------------------------------------------------------------*/
/* Log configuration */
/*---------------------------------------------------------------------------*/
#include "sys/log.h"
#define LOG_MODULE "FR5969"
#define LOG_LEVEL LOG_LEVEL_MAIN

/*---------------------------------------------------------------------------*/
static void
set_lladdr(void)
{
  linkaddr_t addr;

  memset(&addr, 0, sizeof(linkaddr_t));
  /* Use node_id for link layer address since there's no unique ID chip */
  addr.u8[0] = (node_id >> 8) & 0xff;
  addr.u8[1] = node_id & 0xff;
  linkaddr_set_node_addr(&addr);
}
/*---------------------------------------------------------------------------*/
void
platform_init_stage_one(void)
{
  /* Initialize hardware */
  msp430_cpu_init();

  leds_init();
  leds_on(LEDS_RED);
}
/*---------------------------------------------------------------------------*/
void
platform_init_stage_two(void)
{
  /* Initialize UART for serial communication */
  uart0_init(BAUD2UBR(UART0_CONF_BAUD_RATE));

  /*
   * Delay to allow the XDS110 debug probe to fully disconnect and switch
   * to UART passthrough mode. The debug probe buffers UART data while a
   * debug session is active. This delay ensures serial output occurs after
   * the debugger has released the device. Experimentally, 200ms is the
   * minimum; we use 250ms for margin. The argument to __delay_cycles must
   * be a compile-time constant, so derive it from F_CPU.
   */
  __delay_cycles(F_CPU / 4);

  leds_on(LEDS_GREEN);

  /* Set link-layer address */
  set_lladdr();

  leds_off(LEDS_RED);

  LOG_INFO("Platform: MSP-EXP430FR5969 LaunchPad\n");
}
/*---------------------------------------------------------------------------*/
void
platform_init_stage_three(void)
{
  LOG_INFO("Node ID: %u\n", node_id);

  /* Enable serial line input */
  uart0_set_input(serial_line_input_byte);
  serial_line_init();

  leds_off(LEDS_GREEN);
}
/*---------------------------------------------------------------------------*/
void
platform_idle(void)
{
  int s = splhigh();  /* Disable interrupts */

  /* Check if we can go to sleep */
  if(process_nevents() != 0 || uart0_active()) {
    splx(s);  /* Re-enable interrupts */
  } else {
    /* Re-enable interrupts and go to sleep atomically */
    ENERGEST_SWITCH(ENERGEST_TYPE_CPU, ENERGEST_TYPE_LPM);
    watchdog_stop();

    /* Check if DCO needs to be on - if so, only LPM1 */
    if(msp430_dco_required) {
      _BIS_SR(GIE | CPUOFF);  /* LPM1 sleep */
    } else {
      _BIS_SR(GIE | SCG0 | SCG1 | CPUOFF);  /* LPM3 sleep */
    }

    watchdog_start();
    ENERGEST_SWITCH(ENERGEST_TYPE_LPM, ENERGEST_TYPE_CPU);
  }
}
/*---------------------------------------------------------------------------*/
