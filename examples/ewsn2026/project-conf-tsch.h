/*
 * Copyright (c) 2026, Fraunhofer SIT
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

#ifndef PROJECT_CONF_H_
#define PROJECT_CONF_H_

/* configure TSCH/Orchestra */
#define TSCH_CONF_AUTOSTART 0
/* enable security */
#define LLSEC802154_CONF_ENABLED 1
#define TSCH_SECURITY_CONF_SEC_LEVEL_ACK 1
#define TSCH_SECURITY_CONF_SEC_LEVEL_OTHER 1
#define TSCH_SECURITY_CONF_SEC_LEVEL_EB 1
/* align retransmissions with those of CSL */
#define TSCH_CONF_MAC_MAX_FRAME_RETRIES 5
/* align queuebuf slots with CSL */
#define QUEUEBUF_CONF_NUM 64

/* configure Energest */
#define ENERGEST_CONF_ON 1
#if ENERGEST_CONF_ON
#define LPM_CONF_ENABLE 0
#endif /* ENERGEST_CONF_ON */

/* enable/disable logging */
#define LOG_CONF_LEVEL_MAC 0
#define LOG_CONF_LEVEL_FRAMER 0
#define LOG_CONF_LEVEL_6LOWPAN 0
#define LOG_CONF_LEVEL_RPL 0
#define LOG_CONF_LEVEL_MAIN 0

#endif /* PROJECT_CONF_H_ */
