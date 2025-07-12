/*
 * Copyright (c) 2025, Konrad-Felix Krentz
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
 */

#include "contiki.h"
#include "lib/random.h"
#include "unit-test/unit-test.h"
#include <stdio.h>
#include <string.h>

PROCESS(test_random_process, "test");
AUTOSTART_PROCESSES(&test_random_process);

/*---------------------------------------------------------------------------*/
/*
 * ./RNG_output sfc32 16 0x00000000000000 | od -A n -t x1
 * gives
 * c3 76 46 51 df 09 a8 08 2b 9d 34 30 20 c5 52 fb
 */
UNIT_TEST_REGISTER(conformance_1, "Test conformance to PractRand (1/2)");
UNIT_TEST(conformance_1)
{
  UNIT_TEST_BEGIN();

  random_init(0ULL);

  static const unsigned short oracle_outputs[] = {
    0x76c3, 0x5146, 0x09df, 0x08a8, 0x9d2b, 0x3034, 0xc520, 0xfb52
  };
  for(size_t i = 0;
      i < sizeof(oracle_outputs) / sizeof(oracle_outputs[0]);
      i++) {
    UNIT_TEST_ASSERT(oracle_outputs[i] == random_rand());
  }

  UNIT_TEST_END();
}
/*---------------------------------------------------------------------------*/
/*
 * ./RNG_output sfc32 16 0x0102030405060708 | od -A n -t x1
 * 1b 7a 18 78 89 f4 2f 22 b6 5c a8 c6 1b 21 cf 51
 */
UNIT_TEST_REGISTER(conformance_2, "Test conformance to PractRand (2/2)");
UNIT_TEST(conformance_2)
{
  UNIT_TEST_BEGIN();

  random_init(0x0102030405060708ULL);

  static const unsigned short oracle_outputs[] = {
    0x7a1b, 0x7818, 0xf489, 0x222f, 0x5cb6, 0xc6a8, 0x211b, 0x51cf
  };
  for(size_t i = 0;
      i < sizeof(oracle_outputs) / sizeof(oracle_outputs[0]);
      i++) {
    UNIT_TEST_ASSERT(oracle_outputs[i] == random_rand());
  }
  UNIT_TEST_END();
}
/*---------------------------------------------------------------------------*/
PROCESS_THREAD(test_random_process, ev, data)
{
  PROCESS_BEGIN();

  printf("Run unit-test\n");
  printf("---\n");

  UNIT_TEST_RUN(conformance_1);
  UNIT_TEST_RUN(conformance_2);

  if(!UNIT_TEST_PASSED(conformance_1)
     || !UNIT_TEST_PASSED(conformance_2)) {
    printf("=check-me= FAILED\n");
    printf("---\n");
  }

  printf("=check-me= DONE\n");
  printf("---\n");

  PROCESS_END();
}
/*---------------------------------------------------------------------------*/
