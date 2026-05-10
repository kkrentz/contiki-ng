/*
 * Copyright (c) 2026, RISE Research Institutes of Sweden AB
 * All rights reserved.
 *
 * Author: Joakim Eriksson <joakim.eriksson@ri.se>
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

/**
 * \file
 *      Board-specific button initialization for Seeed XIAO nRF54L15
 */

#include "contiki.h"
#include "dev/button-hal.h"

/* Stub implementations to avoid nrfx v2.x API dependency */
#include <stddef.h>

/* Provide empty button list */
button_hal_button_t *button_hal_buttons[] = { NULL };
unsigned char button_hal_button_cnt = 0;

/* Stub for v2.x API compatibility */
/*---------------------------------------------------------------------------*/
void
nrfx_gpiote_in_event_enable(unsigned int pin, unsigned char enable)
{
  /* Stub - no buttons to enable */
}
/*---------------------------------------------------------------------------*/
