/*
 * Copyright (c) 2023, RISE Research Institutes of Sweden
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

/*
 * Authors: Niclas Finne <niclas.finne@ri.se>
 *          Nicolas Tsiftes <nicolas.tsiftes@ri.se>
 */

#include "contiki.h"
#include "sys/autostart.h"
#include "tz-api.h"

#include <arm_cmse.h>
#include <stdarg.h>
#include <string.h>

static struct tz_api tz_api;
static bool initialized;
static volatile bool ns_poll_pending;

/*---------------------------------------------------------------------------*/
#include "sys/log.h"
#define LOG_MODULE "TZAPI"
#define LOG_LEVEL LOG_LEVEL_INFO
/*---------------------------------------------------------------------------*/
process_event_t trustzone_init_event;
/*---------------------------------------------------------------------------*/
CC_TRUSTZONE_SECURE_CALL bool
tz_api_init(struct tz_api *apip)
{
  if(initialized || apip == NULL) {
    return false;
  }

  apip = cmse_check_address_range(apip, sizeof(*apip), CMSE_NONSECURE);
  if(apip == NULL || apip->request_poll == NULL) {
    return false;
  }

  ns_poll_t poll_fn = cmse_nsfptr_create(apip->request_poll);
  if(!cmse_is_nsfptr(poll_fn)) {
    return false;
  }

  trustzone_init_event = process_alloc_event();
  tz_api.request_poll = poll_fn;

  initialized = true;

  for(size_t i = 0; autostart_processes[i] != NULL; i++) {
    process_post(autostart_processes[i], trustzone_init_event, NULL);
  }

  return true;
}
/*---------------------------------------------------------------------------*/
CC_TRUSTZONE_SECURE_CALL bool
tz_api_poll(void)
{
  static volatile bool is_poll_running;

  if(!initialized || is_poll_running) {
    return false;
  }
  is_poll_running = true;

  process_num_events_t event_count = process_nevents();

  if(event_count > 0) {
    LOG_DBG("Processing %u event%s at %lu\n", event_count,
	    event_count == 1 ? "" : "s", (unsigned long)clock_time());
  }

  while(event_count-- > 0) {
    process_run();
    watchdog_periodic();
  }

  is_poll_running = false;

  if(ns_poll_pending) {
    ns_poll_pending = false;
    tz_api.request_poll();
  }

  return process_nevents() > 0;
}
/*---------------------------------------------------------------------------*/
#define TZ_API_PRINTLN_MAX_LEN 256

CC_TRUSTZONE_SECURE_CALL void
tz_api_println(const char *text, size_t len)
{
  if(len > TZ_API_PRINTLN_MAX_LEN) {
    len = TZ_API_PRINTLN_MAX_LEN;
  }
  if(text == NULL || len == 0 ||
     cmse_check_address_range((void *)text, len,
                              CMSE_NONSECURE) == NULL) {
    return;
  }
  printf("n> %.*s\n", (int)len, text);
}
/*---------------------------------------------------------------------------*/
bool
tz_api_request_poll_from_ns(void)
{
  if(!initialized) {
    return false;
  }
  ns_poll_pending = true;
  return true;
}
/*---------------------------------------------------------------------------*/
