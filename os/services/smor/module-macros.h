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
 * \file
 *         Autoconfiguration.
 * \author
 *         Konrad Krentz <konrad.krentz@gmail.com>
 */

#define SMOR
#define NETSTACK_CONF_ROUTING smor_l3_routing_driver
#define UIP_CONF_DS6_LL_NUD 0
#define UIP_CONF_IPV6_QUEUE_PKT 0
#define UIP_CONF_MAX_ROUTES 0
#define UIP_CONF_ND6_AUTOFILL_NBR_CACHE 0
#define UIP_CONF_ND6_SEND_NS 0
#define UIP_CONF_ND6_SEND_RA 0
#define UIP_CONF_ND6_SEND_NA 0
#define UIP_CONF_ROUTER 1
#define SICSLOWPAN_CONF_WITH_MESH_ADDRESSING 1
#define SICSLOWPAN_CONF_WITH_DEDUPLICATION 1
#define SICSLOWPAN_CONF_FRAGMENT_ALWAYS 1
#define AKES_MAC_CONF_UNICAST_SEC_LVL 2
#define CSL_SYNCHRONIZER_CONF smor_l2_synchronizer
