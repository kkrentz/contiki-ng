/*
 * Copyright (c) 2026, RISE Research Institutes of Sweden AB
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
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
 * \file
 *         GPIO HAL backend for MSP-EXP430FR5969 LaunchPad
 *
 *         Configuration helpers and port ISRs that dispatch to the
 *         platform-independent gpio_hal_event_handler().
 */

#include "contiki.h"
#include "dev/gpio-hal.h"
#include "isr_compat.h"
#include <msp430.h>

/*---------------------------------------------------------------------------*/
void
gpio_hal_arch_init(void)
{
  /* msp430_cpu_init() already clears LOCKLPM5 and drives the GPIOs to
   * known states, so there is nothing FR5969-specific to do here. */
}
/*---------------------------------------------------------------------------*/
void
gpio_hal_arch_port_pin_cfg_set(gpio_hal_port_t port, gpio_hal_pin_t pin,
                               gpio_hal_pin_cfg_t cfg)
{
  uint8_t m = (uint8_t)1 << pin;
  uint8_t nm = (uint8_t)~m;
  uint8_t pull = cfg & GPIO_HAL_PIN_CFG_PULL_MASK;
  uint8_t edge = cfg & GPIO_HAL_PIN_CFG_EDGE_BOTH;
  uint8_t int_en = (cfg & GPIO_HAL_PIN_CFG_INT_MASK) ==
                   GPIO_HAL_PIN_CFG_INT_ENABLE;

  /* Pull resistor: REN=0 disables it; REN=1 + OUT selects up (1) or down (0). */
  switch(port) {
  case 1:
    if(pull == GPIO_HAL_PIN_CFG_PULL_NONE) {
      P1REN &= nm;
    } else {
      P1REN |= m;
      if(pull == GPIO_HAL_PIN_CFG_PULL_UP) { P1OUT |= m; }
      else                                 { P1OUT &= nm; }
    }
    /* Edge: IES=1 selects high-to-low. EDGE_BOTH is not supported by the
     * hardware; the closest match (falling) is used. */
    if(edge == GPIO_HAL_PIN_CFG_EDGE_RISING) { P1IES &= nm; }
    else                                     { P1IES |= m; }
    P1IFG &= nm;
    if(int_en) { P1IE |= m; } else { P1IE &= nm; }
    break;
  case 2:
    if(pull == GPIO_HAL_PIN_CFG_PULL_NONE) {
      P2REN &= nm;
    } else {
      P2REN |= m;
      if(pull == GPIO_HAL_PIN_CFG_PULL_UP) { P2OUT |= m; }
      else                                 { P2OUT &= nm; }
    }
    if(edge == GPIO_HAL_PIN_CFG_EDGE_RISING) { P2IES &= nm; }
    else                                     { P2IES |= m; }
    P2IFG &= nm;
    if(int_en) { P2IE |= m; } else { P2IE &= nm; }
    break;
  case 3:
    if(pull == GPIO_HAL_PIN_CFG_PULL_NONE) {
      P3REN &= nm;
    } else {
      P3REN |= m;
      if(pull == GPIO_HAL_PIN_CFG_PULL_UP) { P3OUT |= m; }
      else                                 { P3OUT &= nm; }
    }
    if(edge == GPIO_HAL_PIN_CFG_EDGE_RISING) { P3IES &= nm; }
    else                                     { P3IES |= m; }
    P3IFG &= nm;
    if(int_en) { P3IE |= m; } else { P3IE &= nm; }
    break;
  case 4:
    if(pull == GPIO_HAL_PIN_CFG_PULL_NONE) {
      P4REN &= nm;
    } else {
      P4REN |= m;
      if(pull == GPIO_HAL_PIN_CFG_PULL_UP) { P4OUT |= m; }
      else                                 { P4OUT &= nm; }
    }
    if(edge == GPIO_HAL_PIN_CFG_EDGE_RISING) { P4IES &= nm; }
    else                                     { P4IES |= m; }
    P4IFG &= nm;
    if(int_en) { P4IE |= m; } else { P4IE &= nm; }
    break;
  }
}
/*---------------------------------------------------------------------------*/
gpio_hal_pin_cfg_t
gpio_hal_arch_port_pin_cfg_get(gpio_hal_port_t port, gpio_hal_pin_t pin)
{
  uint8_t m = (uint8_t)1 << pin;
  uint8_t ren = 0, out = 0, ies = 0, ie = 0;
  gpio_hal_pin_cfg_t cfg = 0;

  switch(port) {
  case 1: ren = P1REN; out = P1OUT; ies = P1IES; ie = P1IE; break;
  case 2: ren = P2REN; out = P2OUT; ies = P2IES; ie = P2IE; break;
  case 3: ren = P3REN; out = P3OUT; ies = P3IES; ie = P3IE; break;
  case 4: ren = P4REN; out = P4OUT; ies = P4IES; ie = P4IE; break;
  default: return 0;
  }

  if(ren & m) {
    cfg |= (out & m) ? GPIO_HAL_PIN_CFG_PULL_UP : GPIO_HAL_PIN_CFG_PULL_DOWN;
  } else {
    cfg |= GPIO_HAL_PIN_CFG_PULL_NONE;
  }
  cfg |= (ies & m) ? GPIO_HAL_PIN_CFG_EDGE_FALLING : GPIO_HAL_PIN_CFG_EDGE_RISING;
  cfg |= (ie & m) ? GPIO_HAL_PIN_CFG_INT_ENABLE : GPIO_HAL_PIN_CFG_INT_DISABLE;
  return cfg;
}
/*---------------------------------------------------------------------------*/
void
gpio_hal_arch_port_interrupt_enable(gpio_hal_port_t port, gpio_hal_pin_t pin)
{
  uint8_t m = (uint8_t)1 << pin;
  switch(port) {
  case 1: P1IFG &= (uint8_t)~m; P1IE |= m; break;
  case 2: P2IFG &= (uint8_t)~m; P2IE |= m; break;
  case 3: P3IFG &= (uint8_t)~m; P3IE |= m; break;
  case 4: P4IFG &= (uint8_t)~m; P4IE |= m; break;
  }
}
/*---------------------------------------------------------------------------*/
void
gpio_hal_arch_port_interrupt_disable(gpio_hal_port_t port, gpio_hal_pin_t pin)
{
  uint8_t nm = (uint8_t)~((uint8_t)1 << pin);
  switch(port) {
  case 1: P1IE &= nm; break;
  case 2: P2IE &= nm; break;
  case 3: P3IE &= nm; break;
  case 4: P4IE &= nm; break;
  }
}
/*---------------------------------------------------------------------------*/
/* The PnIV register reports the lowest-numbered pending interrupt and
 * clears the corresponding flag when read. We loop until PnIV reads zero
 * to drain bursts in a single ISR entry. */
/*---------------------------------------------------------------------------*/
static inline gpio_hal_pin_mask_t
piv_to_mask(uint16_t iv)
{
  /* PnIV values 0x02..0x10 map to pins 0..7. */
  if(iv < 0x02 || iv > 0x10) {
    return 0;
  }
  return (gpio_hal_pin_mask_t)1 << ((iv - 2) >> 1);
}
/*---------------------------------------------------------------------------*/
ISR(PORT1, port1_isr)
{
  gpio_hal_pin_mask_t pins = 0;
  uint16_t iv;
  while((iv = P1IV) != 0) {
    pins |= piv_to_mask(iv);
  }
  if(pins) {
    gpio_hal_event_handler(1, pins);
  }
}
/*---------------------------------------------------------------------------*/
ISR(PORT2, port2_isr)
{
  gpio_hal_pin_mask_t pins = 0;
  uint16_t iv;
  while((iv = P2IV) != 0) {
    pins |= piv_to_mask(iv);
  }
  if(pins) {
    gpio_hal_event_handler(2, pins);
  }
}
/*---------------------------------------------------------------------------*/
ISR(PORT3, port3_isr)
{
  gpio_hal_pin_mask_t pins = 0;
  uint16_t iv;
  while((iv = P3IV) != 0) {
    pins |= piv_to_mask(iv);
  }
  if(pins) {
    gpio_hal_event_handler(3, pins);
  }
}
/*---------------------------------------------------------------------------*/
ISR(PORT4, port4_isr)
{
  gpio_hal_pin_mask_t pins = 0;
  uint16_t iv;
  while((iv = P4IV) != 0) {
    pins |= piv_to_mask(iv);
  }
  if(pins) {
    gpio_hal_event_handler(4, pins);
  }
}
/*---------------------------------------------------------------------------*/
