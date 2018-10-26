/*
 * Copyright (c) 2018, Hasso-Plattner-Institut.
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
 *         Generates CCM inputs as required by ContikiMAC.
 * \author
 *         Konrad Krentz <konrad.krentz@gmail.com>
 */

#include "net/mac/contikimac/contikimac-ccm-inputs.h"
#include "net/mac/contikimac/contikimac.h"
#include "net/packetbuf.h"
#include "net/mac/llsec802154.h"
#include "net/mac/contikimac/contikimac-framer-potr.h"
#include "services/akes/akes-nbr.h"
#include "services/akes/akes-mac.h"

/*---------------------------------------------------------------------------*/
void
contikimac_ccm_inputs_generate_nonce(uint8_t *nonce, int forward)
{
  int is_broadcast;
  const linkaddr_t *addr;
#if CONTIKIMAC_WITH_SECURE_PHASE_LOCK
  uint8_t *hdrptr;
#if CONTIKIMAC_FRAMER_POTR_ILOS_ENABLED
  wake_up_counter_t wuc;
#endif /* CONTIKIMAC_FRAMER_POTR_ILOS_ENABLED */
#endif /* CONTIKIMAC_WITH_SECURE_PHASE_LOCK */

  is_broadcast = packetbuf_holds_broadcast();
#if CONTIKIMAC_FRAMER_POTR_ILOS_ENABLED
  addr = is_broadcast
      ? &linkaddr_null
      : (forward
          ? &linkaddr_node_addr
          : packetbuf_addr(PACKETBUF_ADDR_SENDER));
#else /* CONTIKIMAC_FRAMER_POTR_ILOS_ENABLED */
  addr = is_broadcast
      ? &linkaddr_null
      : (forward
          ? packetbuf_addr(PACKETBUF_ADDR_RECEIVER)
          : &linkaddr_node_addr);
#endif /* CONTIKIMAC_FRAMER_POTR_ILOS_ENABLED */
  memcpy(nonce, addr->u8, LINKADDR_SIZE);
  memset(nonce + LINKADDR_SIZE, 0, 8 - LINKADDR_SIZE);

#if CONTIKIMAC_FRAMER_POTR_ILOS_ENABLED
  if(is_broadcast) {
    wuc = forward
        ? contikimac_get_wake_up_counter(contikimac_get_next_strobe_start() + WAKE_UP_COUNTER_INTERVAL)
        : contikimac_restore_wake_up_counter();
  } else {
    wuc = forward
        ? contikimac_predict_wake_up_counter()
        : contikimac_get_wake_up_counter(contikimac_get_last_wake_up_time());
  }
  wake_up_counter_write(nonce + 8, wuc);
#else /* CONTIKIMAC_FRAMER_POTR_ILOS_ENABLED */
  anti_replay_write_counter(nonce + 8);
#endif /* CONTIKIMAC_FRAMER_POTR_ILOS_ENABLED */

#if CONTIKIMAC_WITH_SECURE_PHASE_LOCK
  hdrptr = packetbuf_hdrptr();
  nonce[12] = is_broadcast
      ? 0xFE
      : hdrptr[contikimac_framer_potr_get_strobe_index_offset(hdrptr[0])];
#else /* CONTIKIMAC_WITH_SECURE_PHASE_LOCK */
  nonce[12] = 0xFE;
#endif /* CONTIKIMAC_WITH_SECURE_PHASE_LOCK */
}
/*---------------------------------------------------------------------------*/
void
contikimac_ccm_inputs_generate_otp_nonce(uint8_t *nonce, int forward)
{
  contikimac_ccm_inputs_generate_nonce(nonce, forward);
  nonce[12] = 0xFF;
}
/*---------------------------------------------------------------------------*/
void
contikimac_ccm_inputs_to_acknowledgement_nonce(uint8_t *nonce)
{
#if CONTIKIMAC_FRAMER_POTR_ILOS_ENABLED
  uint8_t i;
  for(i = 0; i < 8; i++) {
    nonce[i] = ~nonce[i];
  }
#else /* CONTIKIMAC_FRAMER_POTR_ILOS_ENABLED */
  nonce[12] = 0xFE;
#endif /* CONTIKIMAC_FRAMER_POTR_ILOS_ENABLED */
}
/*---------------------------------------------------------------------------*/
