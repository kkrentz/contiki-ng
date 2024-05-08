/*
 * Copyright (c) 2024, Siemens AG.
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
#include "tiny-dice.h"

/* Log configuration */
#include "sys/log.h"
#define LOG_MODULE "Benchmark"
#define LOG_LEVEL LOG_LEVEL_DBG

PROCESS(bench_process, "bench_process");
AUTOSTART_PROCESSES(&bench_process);
static const uint8_t reconstruction_data[] = {
  0x01,
  0xEA, 0x8B, 0xCF, 0xD6, 0x3A, 0x21, 0x2E, 0x04,
  0x68, 0xF6, 0x96, 0x5B, 0x3F, 0x3B, 0x15, 0x31,
  0x7C, 0xE5, 0xC7, 0xC2, 0xF1, 0x0C, 0xB1, 0xD3,
  0x28, 0x77, 0x80, 0xB6, 0xC7, 0xFC, 0xF6, 0x88
};
static const char subject[8];

/*---------------------------------------------------------------------------*/
static void
write_compressed_cert(void)
{
  tiny_dice_cert_t cert;
  uint8_t certificate[TINY_DICE_MAX_CERT_SIZE];
  cbor_writer_state_t writer_state;

  tiny_dice_clear_cert(&cert);
  memcpy(cert.reconstruction_data,
         reconstruction_data,
         sizeof(reconstruction_data));
  cert.tci_version = 1;

  cbor_init_writer(&writer_state, certificate, sizeof(certificate));
  tiny_dice_write_cert(&writer_state, &cert);
  size_t certificate_size = cbor_end_writer(&writer_state);
  if(certificate_size == SIZE_MAX) {
    LOG_ERR("cbor_end_writer failed\n");
    return;
  }
  LOG_DBG("Length of compressed certificate: %zu bytes\n", certificate_size);
}
/*---------------------------------------------------------------------------*/
PROCESS_THREAD(bench_process, ev, data)
{
  int result;

  PROCESS_BEGIN();

  write_compressed_cert();
  tiny_dice_set_subject_text(subject, sizeof(subject));

#if 1
  /* issue Cert_L0 */
  PROCESS_PT_SPAWN(&tiny_dice_pt, tiny_dice_issue_cert_l0(&result));
  if(result) {
    LOG_ERR("tiny_issue_cert_l0 failed\n");
    PROCESS_EXIT();
  }
#endif

  PROCESS_PT_SPAWN(&tiny_dice_pt, tiny_dice_boot(&result));
  LOG_INFO("tiny_dice_boot %s\n", result ? "failed" : "succeeded");

  PROCESS_END();
}
/*---------------------------------------------------------------------------*/
