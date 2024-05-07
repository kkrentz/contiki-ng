/*
 * Copyright (c) 2021, Uppsala universitet.
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
 *         Demonstrates the usage of the filtering client.
 * \author
 *         Konrad Krentz <konrad.krentz@gmail.com>
 */

#ifndef PROJECT_CONF_H_
#define PROJECT_CONF_H_

/* Configure CoAP */
#include "coap_config.h"
#define LOG_CONF_LEVEL_COAP 5
#if 1
/* enable OSCORE-NG (uncomment OSCORE-NG module in Makefile, too) */
#undef COAP_OSCORE_NG_SUPPORT
#define COAP_OSCORE_NG_SUPPORT 1
#endif
#if 0
/* enable OSCORE (add OSCORE module to Makefile) */
#undef COAP_OSCORE_SUPPORT
#define COAP_OSCORE_SUPPORT 1
#undef HEAPMEM_CONF_ARENA_SIZE
#define HEAPMEM_CONF_ARENA_SIZE (4096 * 4)
#endif

/* Configure MAC layer */
#define LINKADDR_CONF_SIZE 2
/* for security on lower layers, uncomment these */
/*#define CSL_CONF_COMPLIANT 0
#include "net/mac/csl/csl-autoconf.inc"*/

#endif /* PROJECT_CONF_H_ */
