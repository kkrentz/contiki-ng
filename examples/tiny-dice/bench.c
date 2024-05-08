/*
 * Copyright (c) 2024, Siemens AG
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
 *         Benchmarks for TinyDICE.
 * \author
 *         Konrad Krentz <konrad.krentz@gmail.com>
 */

#include "contiki.h"
#include "coap3/coap_internal.h"
#include "lib/sha-256.h"
#include "net/linkaddr.h"
#include "tiny-dice-ca.h"
#include "tiny-dice-l0.h"
#include "tiny-dice-l1.h"
#include "tiny-dice-csprng.h"
#include "tiny-dice-rot.h"
#include <stdint.h>

/* Log configuration */
#include "sys/log.h"
#define LOG_MODULE "Benchmark"
#define LOG_LEVEL LOG_LEVEL_DBG

#ifdef WITH_CERT_L0
static const uint32_t tci_l0_version = 1;
#endif /* WITH_CERT_L0 */
static const uint8_t tci_l1[TINY_DICE_TCI_SIZE] = {
  0xe4, 0x40, 0x26, 0x24, 0x29, 0xfa, 0x0f, 0xa2,
  0x16, 0x0d, 0xe8, 0x78, 0xb6, 0x26, 0x7d, 0xb9,
  0xb1, 0x08, 0xfe, 0x56, 0xaa, 0x34, 0xaf, 0x3b,
  0xf0, 0x47, 0xdc, 0x14, 0xf9, 0x03, 0xe6, 0xad
};
static const uint32_t tci_l1_version = 1;
static const tiny_dice_tci_mapping_t tci_l1_mapping = {
  tci_l1, tci_l1_version
};
PROCESS(bench_process, "bench_process");
AUTOSTART_PROCESSES(&bench_process);

/*---------------------------------------------------------------------------*/
PROCESS_THREAD(bench_process, ev, data)
{
  static union {
#ifdef WITH_CERT_L0
    struct tiny_dice_ca_context ca;
#endif /* WITH_CERT_L0 */
    struct tiny_dice_l0_context l0;
  } contexts;
  static tiny_dice_cert_chain_t cert_chain;
#ifdef WITH_CERT_L0
  static uint8_t s_l0[ECC_CURVE_P_256_SIZE];
#else /* WITH_CERT_L0 */
  static const uint8_t *s_l0 = NULL;
#endif /* WITH_CERT_L0 */
  int result;

  PROCESS_BEGIN();

  if(!tiny_dice_rot_boot()) {
    LOG_ERR("tiny_dice_rot_boot failed\n");
    PROCESS_EXIT();
  }

#ifdef WITH_CERT_L0
  /* request Cert_L0 */
  tiny_dice_init_cert_chain(&cert_chain, 2);
  cert_chain.certs[0].subject_data = linkaddr_node_addr.u8;
  cert_chain.certs[0].subject_size = LINKADDR_SIZE;
  cert_chain.certs[0].tci_version = tci_l0_version;
  contexts.ca.cert_l0 = cert_chain.certs;
  PROCESS_PT_SPAWN(&contexts.ca.pt,
                   tiny_dice_ca_request(&contexts.ca, s_l0, &result));
  if(result) {
    LOG_ERR("tiny_dice_ca_request failed\n");
    PROCESS_EXIT();
  }
  tiny_dice_csprng_reset();
#else /* WITH_CERT_L0 */
  tiny_dice_init_cert_chain(&cert_chain, 1);
#endif /* WITH_CERT_L0 */

  /* run Layer 0 */
  contexts.l0.cert_chain = &cert_chain;
  cert_chain.certs[cert_chain.length - 1].subject_data = linkaddr_node_addr.u8;
  cert_chain.certs[cert_chain.length - 1].subject_size = LINKADDR_SIZE;
  cert_chain.certs[cert_chain.length - 1].tci_digest = tci_l1;
  PROCESS_PT_SPAWN(&contexts.l0.pt,
                   tiny_dice_l0_boot(&contexts.l0, s_l0, &result));
  if(result) {
    LOG_ERR("tiny_dice_l0_boot failed\n");
    PROCESS_EXIT();
  }

  tiny_dice_compress_cert_chain(&tci_l1_mapping, &cert_chain);
  for (size_t i = 0; i < cert_chain.length; i++) {
    uint8_t cert_bytes[TINY_DICE_MAX_CERT_SIZE];
    cbor_writer_state_t writer;
    cbor_init_writer(&writer, cert_bytes, sizeof(cert_bytes));
    tiny_dice_write_cert(&writer, cert_chain.certs + i);
    size_t cert_size = cbor_end_writer(&writer);
    if(!cert_size) {
      LOG_ERR("cbor_end_writer failed\n");
      PROCESS_EXIT();
    }
    LOG_DBG("Length of compressed certificate: %zu bytes\n", cert_size);
  }

  PROCESS_END();
}
/*---------------------------------------------------------------------------*/
