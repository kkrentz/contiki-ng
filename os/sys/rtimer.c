/*
 * Copyright (c) 2005, Swedish Institute of Computer Science
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
 *
 * This file is part of the Contiki operating system.
 *
 */

/**
 * \file
 *         Implementation of the architecture-agnostic parts of the real-time timer module.
 * \author
 *         Adam Dunkels <adam@sics.se>
 *
 */

/**
 * \addtogroup rt
 * @{
 */

#include "sys/rtimer.h"
#include "contiki.h"

#include "sys/log.h"
#define LOG_MODULE "RTimer"
#define LOG_LEVEL LOG_LEVEL_NONE

static struct rtimer *next_rtimer;

/*---------------------------------------------------------------------------*/
int
rtimer_set(struct rtimer *rtimer, rtimer_clock_t time,
	   rtimer_clock_t duration,
	   rtimer_callback_t func, void *ptr)
{
  LOG_DBG("rtimer_set time %" RTIMER_PRI "\n", time);

  if(next_rtimer) {
    return RTIMER_ERR_ALREADY_SCHEDULED;
  }

  rtimer->func = func;
  rtimer->ptr = ptr;

  rtimer->time = time;
  next_rtimer = rtimer;

  rtimer_arch_schedule(time);
  return RTIMER_OK;
}
/*---------------------------------------------------------------------------*/
int
rtimer_set_precise(struct rtimer *rtimer)
{
  if(next_rtimer) {
    return RTIMER_ERR_ALREADY_SCHEDULED;
  }

  int result = rtimer_arch_schedule_precise(rtimer->time);
  if(result == RTIMER_OK) {
    next_rtimer = rtimer;
  }
  return result;
}
/*---------------------------------------------------------------------------*/
void
rtimer_run_next(void)
{
  struct rtimer *t;
  if(next_rtimer == NULL) {
    return;
  }
  t = next_rtimer;
  next_rtimer = NULL;
  t->func(t, t->ptr);
}
/*---------------------------------------------------------------------------*/
bool
rtimer_has_timed_out(rtimer_clock_t timeout)
{
  return RTIMER_CLOCK_LT(timeout, RTIMER_NOW());
}
/*---------------------------------------------------------------------------*/
bool
rtimer_cancel(void)
{
  if(next_rtimer == NULL) {
    return false;
  }
  return rtimer_arch_cancel();
}
/*---------------------------------------------------------------------------*/

/** @}*/
