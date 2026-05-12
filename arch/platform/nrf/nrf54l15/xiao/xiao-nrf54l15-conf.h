/*
 * Copyright (c) 2026, RISE Research Institutes of Sweden AB
 * All rights reserved.
 *
 * Author: Joakim Eriksson <joakim.eriksson@ri.se>
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * Placeholder configuration header for the XIAO nRF54L15 board.
 * Extend with board-specific overrides as the port matures.
 */
#ifndef XIAO_NRF54L15_CONF_H_
#define XIAO_NRF54L15_CONF_H_

/* RTIMER_SECOND is defined by the OS based on RTIMER_ARCH_SECOND */
/* which should come from the CPU/platform architecture files */

/* Disable button-hal for now (no buttons defined, and needs v3.x API updates) */
#define BUTTON_HAL_CONF_ENABLED 0
/* Temporarily disable watchdog until we implement feeding it */
#define WATCHDOG_CONF_ENABLE 0

#endif /* XIAO_NRF54L15_CONF_H_ */
