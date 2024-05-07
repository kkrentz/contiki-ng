/*
 * Copyright (c) 2023, Uppsala universitet.
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
 */

/**
 * \file
 *         HPI-MAC integration.
 * \author
 *         Konrad Krentz <konrad.krentz@gmail.com>
 */

#ifndef SMOR_L2_H_
#define SMOR_L2_H_

#include "net/mac/frame-queue.h"
#include <stdbool.h>

/**
 * \brief Selects next hops.
 */
bool smor_l2_select_forwarders(
    linkaddr_t forwarders[static FRAME_QUEUE_MAX_FORWARDERS]);

/**
 * \brief Selects a spare forwarder to replace a forwarder who declined.
 */
bool smor_l2_select_spare_forwarder(linkaddr_t *spare_forwarder,
    const linkaddr_t *dest,
    const linkaddr_t *forwarder_to_exclude);

/**
 * \brief Called when an outgoing frame was moved to the packetbuf.
 */
void smor_l2_on_outgoing_frame_loaded(uint_fast8_t burst_index);

/**
 * \brief Tells whether the frame can become part of the current burst.
 */
bool smor_l2_fits_burst(frame_queue_entry_t *fqe);

#endif /* SMOR_L2_H_ */
