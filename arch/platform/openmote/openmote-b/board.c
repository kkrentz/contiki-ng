/*
 * Copyright (c) 2014, Texas Instruments Incorporated - http://www.ti.com/
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
 *
 * This file is part of the Contiki operating system.
 *
 */
/*---------------------------------------------------------------------------*/
/**
 * \addtogroup openmote-b
 * @{
 *
 * \file
 *  Board-initialisation for the OpenMote-B platform
 */
/*---------------------------------------------------------------------------*/
#include "contiki.h"
#include "antenna.h"
#include "dev/gpio.h"
#include "dev/ioc.h"
#include <stdint.h>
#include <string.h>
/*---------------------------------------------------------------------------*/
/* Log configuration */
#include "sys/log.h"
#define LOG_MODULE "OpenMote-B"
#define LOG_LEVEL LOG_LEVEL_MAIN
/*---------------------------------------------------------------------------*/
static void
configure_unused_pins(void)
{
  /* FIXME */
}
/*---------------------------------------------------------------------------*/
void
board_init()
{
  antenna_init();

#if OPENMOTEB_USE_ATMEL_RADIO
  LOG_INFO("Atmel radio connected to the 2.4 GHz antenna connector\n");
  antenna_select_at86rf215();
#else
  LOG_INFO("TI radio connected to the 2.4 GHz antenna connector\n");
  antenna_select_cc2538();
#endif

  configure_unused_pins();

  /* configure bootloader pin as input */
  GPIO_SOFTWARE_CONTROL(GPIO_PORT_TO_BASE(GPIO_A_NUM),
      GPIO_PIN_MASK(FLASH_CCA_CONF_BOOTLDR_BACKDOOR_PORT_A_PIN));
  GPIO_SET_INPUT(GPIO_PORT_TO_BASE(GPIO_A_NUM),
      GPIO_PIN_MASK(FLASH_CCA_CONF_BOOTLDR_BACKDOOR_PORT_A_PIN));
  ioc_set_over(GPIO_A_NUM,
      FLASH_CCA_CONF_BOOTLDR_BACKDOOR_PORT_A_PIN,
      IOC_OVERRIDE_ANA);
}
/*---------------------------------------------------------------------------*/
/**
 * @}
 */
