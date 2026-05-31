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
/*---------------------------------------------------------------------------*/
/**
 * \file
 *      Clock abstraction layer for nrf_802154 on the nRF5340 network core.
 *
 *      The radio requires the HFCLK to be sourced from the HFXO. On the
 *      nRF5340 (unlike the nRF54L) this is the classic
 *      TASKS_HFCLKSTART / EVENTS_HFCLKSTARTED sequence with no separate
 *      PLL step. The HFXO is pre-started in nrf_802154_clock_init() (with
 *      interrupts enabled) and then kept running, so the library's
 *      hfclk_start() -- which may be called from a critical section --
 *      never has to busy-wait. LFCLK is owned by clock-arch.c (RTC0), so
 *      we never touch it here.
 */
/*---------------------------------------------------------------------------*/
#include "platform/nrf_802154_clock.h"
#include "hal/nrf_clock.h"
#include "nrf.h"

#include <stdbool.h>

static volatile bool hfclk_running;
static volatile bool lfclk_running;
/*---------------------------------------------------------------------------*/
static void
set_constant_latency(bool enable)
{
#if defined(POWER_TASKS_CONSTLAT_TASKS_CONSTLAT_Msk) && \
    defined(POWER_TASKS_LOWPWR_TASKS_LOWPWR_Msk)
  if(enable) {
    NRF_POWER->TASKS_CONSTLAT = 1;
  } else {
    NRF_POWER->TASKS_LOWPWR = 1;
  }
#else
  (void)enable;
#endif
}
/*---------------------------------------------------------------------------*/
static void
hfxo_start_blocking(void)
{
  nrf_clock_event_clear(NRF_CLOCK, NRF_CLOCK_EVENT_HFCLKSTARTED);
  nrf_clock_task_trigger(NRF_CLOCK, NRF_CLOCK_TASK_HFCLKSTART);
  while(!nrf_clock_event_check(NRF_CLOCK, NRF_CLOCK_EVENT_HFCLKSTARTED)) {
  }
  nrf_clock_event_clear(NRF_CLOCK, NRF_CLOCK_EVENT_HFCLKSTARTED);
  hfclk_running = true;
}
/*---------------------------------------------------------------------------*/
void
nrf_802154_clock_init(void)
{
  lfclk_running = true; /* LFCLK is started by clock-arch.c for RTC0. */
  set_constant_latency(false);

  /* Pre-start the HFXO while interrupts are still enabled. */
  hfxo_start_blocking();
}
/*---------------------------------------------------------------------------*/
void
nrf_802154_clock_deinit(void)
{
  /* Nothing to do. */
}
/*---------------------------------------------------------------------------*/
void
nrf_802154_clock_hfclk_start(void)
{
  /*
   * The HFXO is pre-started in nrf_802154_clock_init(), so this is normally
   * a fast path. The library may call this from a critical section, so the
   * emergency start below should not occur in practice.
   */
  if(!hfclk_running) {
    hfxo_start_blocking();
  }
  set_constant_latency(true);
  nrf_802154_clock_hfclk_ready();
}
/*---------------------------------------------------------------------------*/
void
nrf_802154_clock_hfclk_stop(void)
{
  /*
   * Keep the HFXO running so hfclk_start() never has to busy-wait inside a
   * critical section. Only drop the constant-latency request. (A future
   * optimization could actually stop the HFXO for lower idle power; on the
   * nRF5340 that is safe for the RTC, which runs off LFCLK.)
   */
  set_constant_latency(false);
}
/*---------------------------------------------------------------------------*/
bool
nrf_802154_clock_hfclk_is_running(void)
{
  return hfclk_running;
}
/*---------------------------------------------------------------------------*/
void
nrf_802154_clock_lfclk_start(void)
{
  /* LFCLK is already running (clock-arch.c). Do not touch the CLOCK
   * peripheral; just report it ready. */
  lfclk_running = true;
  nrf_802154_clock_lfclk_ready();
}
/*---------------------------------------------------------------------------*/
void
nrf_802154_clock_lfclk_stop(void)
{
  /* Never stop LFCLK -- the system clock (RTC0) and the lptimer (RTC1)
   * depend on it. */
}
/*---------------------------------------------------------------------------*/
bool
nrf_802154_clock_lfclk_is_running(void)
{
  return lfclk_running;
}
/*---------------------------------------------------------------------------*/
