/*
 * Copyright (c) 2017, Hasso-Plattner-Institut.
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

#include "contiki.h"
#include "net/linkaddr.h"
#include "sys/etimer.h"
#include "services/akes/akes-nbr.h"
#include "services/akes/akes-trickle.h"
#include "services/akes/akes-mac.h"
#include "net/mac/wake-up-counter.h"

PROCESS(receiver_process, "receiver_process");
AUTOSTART_PROCESSES(&receiver_process);

/*---------------------------------------------------------------------------*/
PROCESS_THREAD(receiver_process, ev, data)
{
#if AKES_MAC_ENABLED
  static struct etimer periodic_timer;

  PROCESS_BEGIN();

  /* disable neighbor discovery once we have found the sender side */
  etimer_set(&periodic_timer, CLOCK_SECOND / WAKE_UP_COUNTER_RATE);
  while(1) {
    PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&periodic_timer));
    etimer_reset(&periodic_timer);
    if(akes_nbr_head(AKES_NBR_PERMANENT)) {
      akes_trickle_stop();
      break;
    }
  }

  PROCESS_END();
#else /* AKES_MAC_ENABLED */
  PROCESS_BEGIN();
  PROCESS_END();
#endif /* AKES_MAC_ENABLED */
}
/*---------------------------------------------------------------------------*/
