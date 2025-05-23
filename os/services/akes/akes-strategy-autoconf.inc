/*
 * Copyright (c) 2016, Hasso-Plattner-Institut.
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

/**
 * \addtogroup akes
 * @{
 *
 * \file
 *         Autoconfigures the AKES_STRATEGY.
 * \author
 *         Konrad Krentz <konrad.krentz@gmail.com>
 */

#ifndef AKES_NBR_CONF_WITH_PAIRWISE_KEYS
#define AKES_NBR_CONF_WITH_PAIRWISE_KEYS 0
#endif /* AKES_NBR_CONF_WITH_PAIRWISE_KEYS */

#if AKES_NBR_CONF_WITH_PAIRWISE_KEYS
#define AKES_NBR_CONF_WITH_INDICES 1
#ifdef EBEAP
#define AKES_MAC_CONF_STRATEGY akes_coresec_strategy
#ifndef AKES_MAC_CONF_BROADCAST_SEC_LVL
#define AKES_MAC_CONF_BROADCAST_SEC_LVL 6
#endif /* AKES_MAC_CONF_BROADCAST_SEC_LVL */
#define AKES_NBR_CONF_WITH_GROUP_KEYS (AKES_MAC_CONF_BROADCAST_SEC_LVL & 4)
#else /* EBEAP */
#define AKES_MAC_CONF_STRATEGY akes_unicast_strategy
#define AKES_NBR_CONF_WITH_GROUP_KEYS 0
#endif /* EBEAP */
#else /* AKES_NBR_CONF_WITH_PAIRWISE_KEYS */
#define AKES_MAC_CONF_STRATEGY akes_noncoresec_strategy
#define AKES_NBR_CONF_WITH_GROUP_KEYS 1
#endif /* AKES_NBR_CONF_WITH_PAIRWISE_KEYS */
#define PACKETBUF_CONF_WITH_UNENCRYPTED_BYTES AKES_NBR_CONF_WITH_GROUP_KEYS

/** @} */
