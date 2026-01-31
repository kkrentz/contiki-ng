/*
 * Copyright (c) 2026, RISE Research Institutes of Sweden AB.
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
 *         Hardware definitions for MSP-EXP430FR5969 LaunchPad
 */

#ifndef MSP430FR5969_DEF_H_
#define MSP430FR5969_DEF_H_

/*---------------------------------------------------------------------------*/
/* Platform features */
/*---------------------------------------------------------------------------*/
#define PLATFORM_HAS_LEDS    1
#define PLATFORM_HAS_BUTTON  1
#define PLATFORM_HAS_RADIO   0  /* No radio on this LaunchPad */

/*---------------------------------------------------------------------------*/
/* LED HAL configuration - use legacy API (MSP430 has no GPIO HAL) */
/*---------------------------------------------------------------------------*/
#define LEDS_CONF_LEGACY_API 1

/*---------------------------------------------------------------------------*/
/* CPU speed - FR5969 runs at 8MHz by default */
/*---------------------------------------------------------------------------*/
#ifndef F_CPU
#define F_CPU 8000000uL
#endif

/*---------------------------------------------------------------------------*/
/* LED configuration - MSP-EXP430FR5969 LaunchPad
 * LED1 (Red):   P1.0
 * LED2 (Green): P4.6
 *
 * Note: LEDs are on different ports, handled in leds-arch.c
 */
/*---------------------------------------------------------------------------*/
#define LEDS_CONF_RED    0x01  /* P1.0 */
#define LEDS_CONF_GREEN  0x02  /* Mapped to bit 1 for LED API, actual pin is P4.6 */

#define LEDS_CONF_ALL    (LEDS_CONF_RED | LEDS_CONF_GREEN)

/* Hardware pin definitions for LED driver */
#define LEDS_RED_PORT    1
#define LEDS_RED_PIN     0
#define LEDS_GREEN_PORT  4
#define LEDS_GREEN_PIN   6

/*---------------------------------------------------------------------------*/
/* Button configuration
 * S1: P4.5 (directly to ground when pressed)
 * S2: P1.1 (directly to ground when pressed)
 */
/*---------------------------------------------------------------------------*/
#define BUTTON_S1_PORT   4
#define BUTTON_S1_PIN    5
#define BUTTON_S2_PORT   1
#define BUTTON_S2_PIN    1

/*---------------------------------------------------------------------------*/
/* FRAM memory configuration (non-volatile) */
/*---------------------------------------------------------------------------*/
#define FRAM_CONF_START       0x4400
#define FRAM_CONF_SIZE        (64 * 1024UL)  /* 64KB */

/* Info FRAM segment */
#define INFO_FRAM_CONF_START  0x1800
#define INFO_FRAM_CONF_SIZE   512            /* 512B */

/*---------------------------------------------------------------------------*/
/* SRAM configuration (volatile) */
/*---------------------------------------------------------------------------*/
#define SRAM_CONF_START       0x1C00
#define SRAM_CONF_SIZE        (2 * 1024)     /* 2KB */

/*---------------------------------------------------------------------------*/
/* UART configuration - eUSCI_A0 for backchannel */
/*---------------------------------------------------------------------------*/
#ifndef UART0_CONF_BAUD_RATE
#define UART0_CONF_BAUD_RATE  115200
#endif

/*---------------------------------------------------------------------------*/
/* Watchdog configuration */
/*---------------------------------------------------------------------------*/
#define WATCHDOG_CONF_TIMER_A  1

#endif /* MSP430FR5969_DEF_H_ */
