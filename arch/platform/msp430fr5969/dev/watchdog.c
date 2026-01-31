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
 *         Watchdog driver for MSP430FR5969
 */

#include "contiki.h"
#include "dev/watchdog.h"
#include <msp430.h>

static int counter = 0;

/*---------------------------------------------------------------------------*/
void
watchdog_init(void)
{
  /* Stop the watchdog timer */
  WDTCTL = WDTPW | WDTHOLD;
  counter = 0;
}
/*---------------------------------------------------------------------------*/
void
watchdog_start(void)
{
  /* Make sure we're not counting down */
  counter--;
  if(counter == 0) {
    /* Configure watchdog for ~1 second timeout @ 8MHz:
     * WDTSSEL = SMCLK, WDTIS = /8192 => ~1ms per tick
     * Or use ACLK with /32768 for ~1s at 32kHz
     * Here we use SMCLK/8192/1024 for approximately 1 second timeout
     */
    WDTCTL = WDTPW | WDTCNTCL | WDTSSEL__SMCLK | WDTIS__8192K;
  }
}
/*---------------------------------------------------------------------------*/
void
watchdog_periodic(void)
{
  /* Clear watchdog counter by rewriting control register */
  WDTCTL = (WDTCTL & 0x00FF) | WDTPW | WDTCNTCL;
}
/*---------------------------------------------------------------------------*/
void
watchdog_stop(void)
{
  counter++;
  if(counter == 1) {
    WDTCTL = WDTPW | WDTHOLD;
  }
}
/*---------------------------------------------------------------------------*/
void
watchdog_reboot(void)
{
  /* Cause a watchdog reset by writing with wrong password */
  WDTCTL = 0;
}
/*---------------------------------------------------------------------------*/
