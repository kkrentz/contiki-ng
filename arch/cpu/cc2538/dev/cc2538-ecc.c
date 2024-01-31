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
 * \addtogroup crypto
 * @{
 *
 * \file
 * Implementation of PKA-accelerated ECDH and ECDSA
 */

#include "lib/ecc.h"
#include "lib/csprng.h"
#include "dev/pka.h"

/* Log configuration */
#include "sys/log.h"
#define LOG_MODULE "ECC"
#define LOG_LEVEL LOG_LEVEL_NONE

#define SCALAR_SPACE \
    (ECC_BYTES / sizeof(uint32_t))
#define REMAINDER_SPACE \
    PKA_REMAINDER_SPACE(SCALAR_SPACE)
#define COORDINATE_SPACE \
    PKA_BUFFERED_LEN(SCALAR_SPACE)
#define POINT_SPACE \
    PKA_POINT_SPACE(SCALAR_SPACE)
#define SCRATCHPAD_SPACE \
    MAX(PKA_MULTIPLY_SCRATCHPAD_SPACE(SCALAR_SPACE, SCALAR_SPACE), \
      MAX(PKA_ADD_SCRATCHPAD_SPACE(SCALAR_SPACE, SCALAR_SPACE), \
        MAX(PKA_SUBTRACT_SCRATCHPAD_SPACE(SCALAR_SPACE, SCALAR_SPACE), \
          MAX(PKA_ECC_ADD_SCRATCHPAD_SPACE(SCALAR_SPACE), \
            MAX(PKA_ECC_MUL_SCRATCHPAD_SPACE(SCALAR_SPACE), \
              PKA_MOD_INV_SCRATCHPAD_SPACE(SCALAR_SPACE, SCALAR_SPACE))))))

/* useful scalars */
static const uint32_t null_scalar[SCALAR_SPACE];
static const uint32_t one_scalar[SCALAR_SPACE] = { 1 };

/* offsets into PKA RAM */
static const uintptr_t null_scalar_offset = 0;
static const uintptr_t one_scalar_offset =
    PKA_NEXT_OFFSET(null_scalar_offset, SCALAR_SPACE);
static const uintptr_t curve_g_offset =
    PKA_NEXT_OFFSET(one_scalar_offset, SCALAR_SPACE);
static const uintptr_t curve_pab_offset =
    PKA_NEXT_OFFSET(curve_g_offset, 2 * COORDINATE_SPACE);
static const uintptr_t curve_n_offset =
    PKA_NEXT_OFFSET(curve_pab_offset, 3 * COORDINATE_SPACE);
static const uintptr_t curve_a_offset =
    PKA_NEXT_OFFSET(curve_n_offset, SCALAR_SPACE);
static const uintptr_t curve_b_offset =
    PKA_NEXT_OFFSET(curve_a_offset, SCALAR_SPACE);
static const uintptr_t scratchpad_offset =
    PKA_NEXT_OFFSET(curve_b_offset, SCALAR_SPACE);
static const uintptr_t variables_offset =
    PKA_NEXT_OFFSET(scratchpad_offset, SCRATCHPAD_SPACE);
static const uintptr_t curve_prime_offset = curve_pab_offset;

/* curve parameters */
static const uint32_t nist_p_256_p_plus_one[8] = {
  0x00000000 , 0x00000000 , 0x00000000 , 0x00000001 ,
  0x00000000 , 0x00000000 , 0x00000001 , 0xffffffff
};
static const uint32_t nist_p_256_p[8] = {
  0xFFFFFFFF , 0xFFFFFFFF , 0xFFFFFFFF , 0x00000000 ,
  0x00000000 , 0x00000000 , 0x00000001 , 0xFFFFFFFF
};
static const uint32_t nist_p_256_n[8] = {
  0xFC632551 , 0xF3B9CAC2 , 0xA7179E84 , 0xBCE6FAAD ,
  0xFFFFFFFF , 0xFFFFFFFF , 0x00000000 , 0xFFFFFFFF
};
static const uint32_t nist_p_256_a[8] = {
  0xFFFFFFFC , 0xFFFFFFFF , 0xFFFFFFFF , 0x00000000 ,
  0x00000000 , 0x00000000 , 0x00000001 , 0xFFFFFFFF
};
static const uint32_t nist_p_256_b[8] = {
  0x27D2604B , 0x3BCE3C3E , 0xCC53B0F6 , 0x651D06B0 ,
  0x769886BC , 0xB3EBBD55 , 0xAA3A93E7 , 0x5AC635D8
};
static const uint32_t nist_p_256_x[8] = {
  0xD898C296 , 0xF4A13945 , 0x2DEB33A0 , 0x77037D81 ,
  0x63A440F2 , 0xF8BCE6E5 , 0xE12C4247 , 0x6B17D1F2
};
static const uint32_t nist_p_256_y[8] = {
  0x37BF51F5 , 0xCBB64068 , 0x6B315ECE , 0x2BCE3357 ,
  0x7C0F9E16 , 0x8EE7EB4A , 0xFE1A7F9B , 0x4FE342E2
};

static struct pt protothreads[2];

/*---------------------------------------------------------------------------*/
static uint32_t
test_bit(const uint32_t *scalar, uint32_t bit)
{
  return scalar[bit >> 5] & ((uint32_t)1 << (bit & 0x1F));
}
/*---------------------------------------------------------------------------*/
static void
scalar_to_pka_ram(const uint8_t network_bytes[static ECC_BYTES],
    uintptr_t offset)
{
  pka_network_bytes_to_pka_ram(network_bytes, ECC_BYTES, offset);
}
/*---------------------------------------------------------------------------*/
static void
scalar_from_pka_ram(uint8_t network_bytes[static ECC_BYTES],
    uintptr_t offset)
{
  pka_network_bytes_from_pka_ram(network_bytes, SCALAR_SPACE, offset);
}
/*---------------------------------------------------------------------------*/
static PT_THREAD(compare_a_and_b(
    uintptr_t a_offset,
    uintptr_t b_offset,
    int *result))
{
  PT_BEGIN(protothreads + 1);

  REG(PKA_APTR) = a_offset;
  REG(PKA_ALENGTH) = SCALAR_SPACE;
  REG(PKA_BPTR) = b_offset;
  pka_run_function(PKA_FUNCTION_COMPARE);
  PT_WAIT_UNTIL(protothreads + 1, pka_check_status());
  if(REG(PKA_COMPARE) == PKA_COMPARE_A_GREATER_THAN_B) {
    *result = PKA_STATUS_A_GR_B;
  } else if(REG(PKA_COMPARE) == PKA_COMPARE_A_LESS_THAN_B) {
    *result = PKA_STATUS_A_LT_B;
  } else {
    *result = PKA_STATUS_A_EQ_B;
  }

  PT_END(protothreads + 1);
}
/*---------------------------------------------------------------------------*/
static PT_THREAD(check_bounds(
    uintptr_t x_offset,
    uintptr_t a_offset,
    uintptr_t b_offset,
    int *result))
{
  PT_BEGIN(protothreads + 1);

  /* check whether x > a */
  REG(PKA_APTR) = x_offset;
  REG(PKA_ALENGTH) = SCALAR_SPACE;
  REG(PKA_BPTR) = a_offset;
  pka_run_function(PKA_FUNCTION_COMPARE);
  PT_WAIT_UNTIL(protothreads + 1, pka_check_status());
  if(REG(PKA_COMPARE) != PKA_COMPARE_A_GREATER_THAN_B) {
    *result = PKA_STATUS_FAILURE;
    PT_EXIT(protothreads + 1);
  }

  /* check whether x < b */
  REG(PKA_BPTR) = b_offset;
  pka_run_function(PKA_FUNCTION_COMPARE);
  PT_WAIT_UNTIL(protothreads + 1, pka_check_status());
  if(REG(PKA_COMPARE) != PKA_COMPARE_A_LESS_THAN_B) {
    *result = PKA_STATUS_FAILURE;
    PT_EXIT(protothreads + 1);
  }

  *result = PKA_STATUS_SUCCESS;

  PT_END(protothreads + 1);
}
/*---------------------------------------------------------------------------*/
static PT_THREAD(invert_modulo(
    uintptr_t number_offset,
    uintptr_t modulus_offset,
    uintptr_t result_offset,
    int *result))
{
  PT_BEGIN(protothreads + 1);

  /* invert number */
  REG(PKA_APTR) = number_offset;
  REG(PKA_ALENGTH) = SCALAR_SPACE;
  REG(PKA_BPTR) = modulus_offset;
  REG(PKA_BLENGTH) = SCALAR_SPACE;
  REG(PKA_DPTR) = scratchpad_offset;
  pka_run_function(PKA_FUNCTION_INVMOD);
  PT_WAIT_UNTIL(protothreads + 1, pka_check_status());

  /* check result */
  if(REG(PKA_MSW) & PKA_MSW_RESULT_IS_ZERO) {
    *result = PKA_STATUS_RESULT_0;
    PT_EXIT(protothreads + 1);
  }

  /* copy result */
  REG(PKA_APTR) = scratchpad_offset;
  REG(PKA_ALENGTH) = SCALAR_SPACE;
  REG(PKA_CPTR) = result_offset;
  pka_run_function(PKA_FUNCTION_COPY);
  PT_WAIT_UNTIL(protothreads + 1, pka_check_status());

  *result = PKA_STATUS_SUCCESS;

  PT_END(protothreads + 1);
}
/*---------------------------------------------------------------------------*/
static PT_THREAD(add_or_multiply_modulo(
    uint32_t function,
    uintptr_t a_offset,
    uintptr_t b_offset,
    uintptr_t modulus_offset,
    uintptr_t result_offset,
    int *result))
{
  PT_BEGIN(protothreads + 1);

  /* add or multiply */
  REG(PKA_APTR) = a_offset;
  REG(PKA_ALENGTH) = SCALAR_SPACE;
  REG(PKA_BPTR) = b_offset;
  REG(PKA_BLENGTH) = SCALAR_SPACE;
  REG(PKA_CPTR) = scratchpad_offset;
  pka_run_function(function);
  PT_WAIT_UNTIL(protothreads + 1, pka_check_status());

  /* check result */
  if(REG(PKA_MSW) & PKA_MSW_RESULT_IS_ZERO) {
    *result = PKA_STATUS_RESULT_0;
    PT_EXIT(protothreads + 1);
  }

  /* compute modulus */
  REG(PKA_APTR) = scratchpad_offset;
  REG(PKA_ALENGTH) = MAX(SCALAR_SPACE,
      (REG(PKA_MSW) & PKA_MSW_MSW_ADDRESS_M) - scratchpad_offset + 1);
  REG(PKA_BPTR) = modulus_offset;
  REG(PKA_CPTR) = result_offset;
  pka_run_function(PKA_FUNCTION_MODULO);
  PT_WAIT_UNTIL(protothreads + 1, pka_check_status());

  *result = PKA_STATUS_SUCCESS;

  PT_END(protothreads + 1);
}
/*---------------------------------------------------------------------------*/
static PT_THREAD(subtract(
    uintptr_t a_offset,
    uintptr_t b_offset,
    uintptr_t result_offset))
{
  PT_BEGIN(protothreads + 1);

  /* subtract */
  REG(PKA_APTR) = a_offset;
  REG(PKA_ALENGTH) = SCALAR_SPACE;
  REG(PKA_BPTR) = b_offset;
  REG(PKA_BLENGTH) = SCALAR_SPACE;
  REG(PKA_CPTR) = scratchpad_offset;
  pka_run_function(PKA_FUNCTION_SUBTRACT);
  PT_WAIT_UNTIL(protothreads + 1, pka_check_status());

  /* copy result */
  REG(PKA_APTR) = scratchpad_offset;
  REG(PKA_ALENGTH) = SCALAR_SPACE;
  REG(PKA_CPTR) = result_offset;
  pka_run_function(PKA_FUNCTION_COPY);
  PT_WAIT_UNTIL(protothreads + 1, pka_check_status());

  PT_END(protothreads + 1);
}
/*---------------------------------------------------------------------------*/
static PT_THREAD(add_or_multiply_point(
    uint32_t function,
    uintptr_t a_offset,
    uintptr_t c_offset,
    uintptr_t result_offset,
    int *result))
{
  PT_BEGIN(protothreads + 1);

  /* add or multiply point */
  REG(PKA_APTR) = a_offset;
  REG(PKA_ALENGTH) = SCALAR_SPACE;
  REG(PKA_BPTR) = curve_pab_offset;
  REG(PKA_BLENGTH) = SCALAR_SPACE;
  REG(PKA_CPTR) = c_offset;
  REG(PKA_DPTR) = scratchpad_offset;
  pka_run_function(function);
  PT_WAIT_UNTIL(protothreads + 1, pka_check_status());

  /* check result */
  if(REG(PKA_SHIFT) == PKA_SHIFT_POINT_AT_INFINITY) {
    *result = PKA_STATUS_POINT_AT_INFINITY;
    PT_EXIT(protothreads + 1);
  }
  if(REG(PKA_SHIFT) != PKA_SHIFT_SUCCESS) {
    *result = PKA_STATUS_FAILURE;
    PT_EXIT(protothreads + 1);
  }

  /* copy result */
  REG(PKA_APTR) = scratchpad_offset;
  REG(PKA_ALENGTH) = POINT_SPACE;
  REG(PKA_CPTR) = result_offset;
  pka_run_function(PKA_FUNCTION_COPY);
  PT_WAIT_UNTIL(protothreads + 1, pka_check_status());

  *result = PKA_STATUS_SUCCESS;

  PT_END(protothreads + 1);
}
/*---------------------------------------------------------------------------*/
static void
enable(void)
{
  pka_init();
  pka_words_to_pka_ram(null_scalar,
      SCALAR_SPACE,
      null_scalar_offset);
  pka_words_to_pka_ram(one_scalar,
      SCALAR_SPACE,
      one_scalar_offset);
  pka_words_to_pka_ram(nist_p_256_x,
      SCALAR_SPACE, curve_g_offset);
  pka_words_to_pka_ram(nist_p_256_y,
      SCALAR_SPACE,
      curve_g_offset + COORDINATE_SPACE);
  pka_words_to_pka_ram(nist_p_256_p,
      SCALAR_SPACE,
      curve_pab_offset);
  pka_words_to_pka_ram(nist_p_256_a,
      SCALAR_SPACE,
      curve_pab_offset + COORDINATE_SPACE);
  pka_words_to_pka_ram(nist_p_256_b,
      SCALAR_SPACE,
      curve_pab_offset + (COORDINATE_SPACE * 2));
  pka_words_to_pka_ram(nist_p_256_n,
      SCALAR_SPACE,
      curve_n_offset);
  pka_words_to_pka_ram(nist_p_256_a,
      SCALAR_SPACE,
      curve_a_offset);
  pka_words_to_pka_ram(nist_p_256_b,
      SCALAR_SPACE,
      curve_b_offset);
}
/*---------------------------------------------------------------------------*/
static struct pt *
get_protothread(void)
{
  return protothreads;
}
/*---------------------------------------------------------------------------*/
static PT_THREAD(validate_public_key(
    const uint8_t public_key[static ECC_BYTES * 2],
    int *result))
{
  static const uintptr_t public_key_x_offset =
      variables_offset;
  static const uintptr_t public_key_y_offset =
      PKA_NEXT_OFFSET(public_key_x_offset, POINT_SPACE);
  static const uintptr_t tmp1_offset =
      PKA_NEXT_OFFSET(public_key_y_offset, SCALAR_SPACE);
  static const uintptr_t tmp2_offset =
      PKA_NEXT_OFFSET(tmp1_offset, REMAINDER_SPACE);
  /* PKA_NEXT_OFFSET(tmp2_offset, REMAINDER_SPACE); */

  PT_BEGIN(protothreads);

  /* copy inputs to PKA RAM */
  scalar_to_pka_ram(public_key, public_key_x_offset);
  scalar_to_pka_ram(public_key + ECC_BYTES, public_key_y_offset);

  /* ensure that 0 < p.x < prime */
  PT_SPAWN(protothreads,
      protothreads + 1,
      check_bounds(public_key_x_offset,
          null_scalar_offset,
          curve_prime_offset,
          result));
  if(*result != PKA_STATUS_SUCCESS) {
    PT_EXIT(protothreads);
  }

  /* ensure that 0 < p.x < prime */
  PT_SPAWN(protothreads,
      protothreads + 1,
      check_bounds(public_key_y_offset,
          null_scalar_offset,
          curve_prime_offset,
          result));
  if(*result != PKA_STATUS_SUCCESS) {
    PT_EXIT(protothreads);
  }

  /* ensure that y^2 = x^3 + ax + b */
  /* tmp1 = y^2 */
  PT_SPAWN(protothreads,
      protothreads + 1,
      add_or_multiply_modulo(PKA_FUNCTION_MULTIPLY,
          public_key_y_offset,
          public_key_y_offset,
          curve_prime_offset,
          tmp1_offset,
          result));
  if(*result != PKA_STATUS_SUCCESS) {
    PT_EXIT(protothreads);
  }

  /* tmp2 = x^2 */
  PT_SPAWN(protothreads,
      protothreads + 1,
      add_or_multiply_modulo(PKA_FUNCTION_MULTIPLY,
          public_key_x_offset,
          public_key_x_offset,
          curve_prime_offset,
          tmp2_offset,
          result));
  if(*result != PKA_STATUS_SUCCESS) {
    PT_EXIT(protothreads);
  }

  /* tmp2 = x^2 + a */
  PT_SPAWN(protothreads,
      protothreads + 1,
      add_or_multiply_modulo(PKA_FUNCTION_ADD,
          tmp2_offset,
          curve_a_offset,
          curve_prime_offset,
          tmp2_offset,
          result));
  if(*result != PKA_STATUS_SUCCESS) {
    PT_EXIT(protothreads);
  }

  /* tmp2 = x^3 + ax */
  PT_SPAWN(protothreads,
      protothreads + 1,
      add_or_multiply_modulo(PKA_FUNCTION_MULTIPLY,
          tmp2_offset,
          public_key_x_offset,
          curve_prime_offset,
          tmp2_offset,
          result));
  if(*result != PKA_STATUS_SUCCESS) {
    PT_EXIT(protothreads);
  }

  /* tmp2 = x^3 + ax + b */
  PT_SPAWN(protothreads,
      protothreads + 1,
      add_or_multiply_modulo(PKA_FUNCTION_ADD,
          tmp2_offset,
          curve_b_offset,
          curve_prime_offset,
          tmp2_offset,
          result));
  if(*result != PKA_STATUS_SUCCESS) {
    PT_EXIT(protothreads);
  }

  PT_SPAWN(protothreads,
      protothreads + 1,
      compare_a_and_b(tmp1_offset, tmp2_offset, result));
  if(*result != PKA_STATUS_A_EQ_B) {
    PT_EXIT(protothreads);
  }

  *result = PKA_STATUS_SUCCESS;

  PT_END(protothreads);
}
/*---------------------------------------------------------------------------*/
static void
compress_public_key(const uint8_t public_key[static ECC_BYTES * 2],
    uint8_t compressed_public_key[static ECC_BYTES + 1])
{
  memcpy(compressed_public_key + 1, public_key, ECC_BYTES);
  compressed_public_key[0] = 2 + (public_key[ECC_BYTES * 2 - 1] & 0x01);
}
/*---------------------------------------------------------------------------*/
static PT_THREAD(decompress_public_key(
    const uint8_t compressed_public_key[static ECC_BYTES + 1],
    uint8_t uncompressed_public_key[static ECC_BYTES * 2],
    int *result))
{
  static const uintptr_t public_key_x_offset =
      variables_offset;
  static const uintptr_t public_key_y_offset =
      PKA_NEXT_OFFSET(public_key_x_offset, SCALAR_SPACE);
  static const uintptr_t mod_sqrt_offset =
      PKA_NEXT_OFFSET(public_key_y_offset, MAX(SCALAR_SPACE, REMAINDER_SPACE));
  /* PKA_NEXT_OFFSET(mod_sqrt_offset, MAX(SCALAR_SPACE, REMAINDER_SPACE)); */
  static uint8_t compression_info;
  static uint8_t i;

  PT_BEGIN(protothreads);

  /* save inputs */
  compression_info = compressed_public_key[0];
  scalar_to_pka_ram(compressed_public_key + 1, public_key_x_offset);

  /* y = x^2 */
  PT_SPAWN(protothreads,
      protothreads + 1,
      add_or_multiply_modulo(PKA_FUNCTION_MULTIPLY,
          public_key_x_offset,
          public_key_x_offset,
          curve_prime_offset,
          public_key_y_offset,
          result));
  if(*result != PKA_STATUS_SUCCESS) {
    PT_EXIT(protothreads);
  }

  /* y = x^2 + a */
  PT_SPAWN(protothreads,
      protothreads + 1,
      add_or_multiply_modulo(PKA_FUNCTION_ADD,
          public_key_y_offset,
          curve_a_offset,
          curve_prime_offset,
          public_key_y_offset,
          result));
  if(*result != PKA_STATUS_SUCCESS) {
    PT_EXIT(protothreads);
  }

  /* y = x^3 + ax */
  PT_SPAWN(protothreads,
      protothreads + 1,
      add_or_multiply_modulo(PKA_FUNCTION_MULTIPLY,
          public_key_y_offset,
          public_key_x_offset,
          curve_prime_offset,
          public_key_y_offset,
          result));
  if(*result != PKA_STATUS_SUCCESS) {
    PT_EXIT(protothreads);
  }

  /* y = x^3 + ax + b */
  PT_SPAWN(protothreads,
      protothreads + 1,
      add_or_multiply_modulo(PKA_FUNCTION_ADD,
          public_key_y_offset,
          curve_b_offset,
          curve_prime_offset,
          public_key_y_offset,
          result));
  if(*result != PKA_STATUS_SUCCESS) {
    PT_EXIT(protothreads);
  }

  /* compute mod sqrt of y */

  /* copy one scalar */
  REG(PKA_APTR) = one_scalar_offset;
  REG(PKA_ALENGTH) = SCALAR_SPACE;
  REG(PKA_CPTR) = mod_sqrt_offset;
  pka_run_function(PKA_FUNCTION_COPY);
  PT_WAIT_UNTIL(protothreads, pka_check_status());

  for(i = 255; i > 1; i--) {
    PT_SPAWN(protothreads,
        protothreads + 1,
        add_or_multiply_modulo(PKA_FUNCTION_MULTIPLY,
            mod_sqrt_offset,
            mod_sqrt_offset,
            curve_prime_offset,
            mod_sqrt_offset,
            result));
    if(*result != PKA_STATUS_SUCCESS) {
      PT_EXIT(protothreads);
    }
    if(test_bit(nist_p_256_p_plus_one, i)) {
      PT_SPAWN(protothreads,
          protothreads + 1,
          add_or_multiply_modulo(PKA_FUNCTION_MULTIPLY,
              mod_sqrt_offset,
              public_key_y_offset,
              curve_prime_offset,
              mod_sqrt_offset,
              result));
      if(*result != PKA_STATUS_SUCCESS) {
        PT_EXIT(protothreads);
      }
    }
  }

  if((pka_word_from_pka_ram(mod_sqrt_offset) & 0x01)
      != (compression_info & 0x01)) {
    PT_SPAWN(protothreads,
        protothreads + 1,
        subtract(curve_prime_offset, mod_sqrt_offset, mod_sqrt_offset));
  }

  scalar_from_pka_ram(uncompressed_public_key, public_key_x_offset);
  scalar_from_pka_ram(uncompressed_public_key + ECC_BYTES, mod_sqrt_offset);
  *result = PKA_STATUS_SUCCESS;

  PT_END(protothreads);
}
/*---------------------------------------------------------------------------*/
static PT_THREAD(sign(
    uint8_t signature[static ECC_SIGNATURE_LEN],
    const uint8_t message_hash[static ECC_BYTES],
    const uint8_t private_key[static ECC_BYTES],
    int *result))
{
  static const uintptr_t e_offset =
      variables_offset;
  static const uintptr_t d_offset =
      PKA_NEXT_OFFSET(e_offset, SCALAR_SPACE);
  static const uintptr_t k_offset =
      PKA_NEXT_OFFSET(d_offset, SCALAR_SPACE);
  static const uintptr_t r_offset =
      PKA_NEXT_OFFSET(k_offset, COORDINATE_SPACE);
  static const uintptr_t s_offset =
      PKA_NEXT_OFFSET(r_offset, POINT_SPACE);
  /* PKA_NEXT_OFFSET(s_offset, REMAINDER_SPACE); */
  uint32_t k[SCALAR_SPACE];

  PT_BEGIN(protothreads);

  /* copy inputs to PKA RAM */
  scalar_to_pka_ram(private_key, d_offset);
  scalar_to_pka_ram(message_hash, e_offset);

  while(1) {
    /* generate k */
    if(!csprng_rand((uint8_t *)k, sizeof(k))) {
      LOG_ERR("CSPRNG error\n");
      *result = PKA_STATUS_FAILURE;
      PT_EXIT(protothreads);
    }
    pka_words_to_pka_ram(k, SCALAR_SPACE, k_offset);
    PT_SPAWN(protothreads,
        protothreads + 1,
        check_bounds(k_offset,
            null_scalar_offset,
            curve_n_offset,
            result));
    if(*result != PKA_STATUS_SUCCESS) {
      LOG_WARN("k was not in [1, n-1]\n");
      continue;
    }

    /* calculate k x G = (r, ignore)*/
    PT_SPAWN(protothreads,
        protothreads + 1,
        add_or_multiply_point(PKA_FUNCTION_ECCMUL,
            k_offset,
            curve_g_offset,
            r_offset,
            result));
    if(*result == PKA_STATUS_POINT_AT_INFINITY) {
      LOG_WARN("k x G is at infinity\n");
      continue;
    }
    if(*result != PKA_STATUS_SUCCESS) {
      LOG_ERR("Line: %u Error: %u\n", __LINE__, *result);
      PT_EXIT(protothreads);
    }

    /* ensure that r != 0 */
    PT_SPAWN(protothreads,
        protothreads + 1,
        compare_a_and_b(null_scalar_offset, r_offset, result));
    if(*result == PKA_STATUS_A_EQ_B) {
      LOG_WARN("r is zero\n");
      continue;
    }

    /* s := rd mod n */
    PT_SPAWN(protothreads,
        protothreads + 1,
        add_or_multiply_modulo(PKA_FUNCTION_MULTIPLY,
            d_offset,
            r_offset,
            curve_n_offset,
            s_offset,
            result));
    if(*result == PKA_STATUS_RESULT_0) {
      LOG_WARN("rd mod n was zero\n");
      continue;
    }
    if(*result != PKA_STATUS_SUCCESS) {
      LOG_ERR("Line: %u Error: %u\n", __LINE__, *result);
      PT_EXIT(protothreads);
    }

    /* ensure that rd and e don't coincide */
    PT_SPAWN(protothreads,
        protothreads + 1,
        compare_a_and_b(e_offset, s_offset, result));
    if(*result == PKA_STATUS_A_EQ_B) {
      LOG_WARN("rd and e coincide\n");
      continue;
    }

    /* s := e + rd mod n */
    PT_SPAWN(protothreads,
        protothreads + 1,
        add_or_multiply_modulo(PKA_FUNCTION_ADD,
            e_offset,
            s_offset,
            curve_n_offset,
            s_offset,
            result));
    if(*result == PKA_STATUS_RESULT_0) {
      LOG_WARN("e + rd mod n was zero\n");
      continue;
    }
    if(*result != PKA_STATUS_SUCCESS) {
      LOG_ERR("Line: %u Error: %u\n", __LINE__, *result);
      PT_EXIT(protothreads);
    }

    /* k := 1 / k */
    PT_SPAWN(protothreads,
        protothreads + 1,
        invert_modulo(k_offset, curve_n_offset, k_offset, result));
    if(*result == PKA_STATUS_RESULT_0) {
      LOG_WARN("inverse of k was zero\n");
      continue;
    }
    if(*result != PKA_STATUS_SUCCESS) {
      LOG_ERR("Line: %u Error: %u\n", __LINE__, *result);
      PT_EXIT(protothreads);
    }

    /* s := (e + r*d) / k mod n */
    PT_SPAWN(protothreads,
        protothreads + 1,
        add_or_multiply_modulo(PKA_FUNCTION_MULTIPLY,
            k_offset,
            s_offset,
            curve_n_offset,
            s_offset,
            result));
    if(*result == PKA_STATUS_RESULT_0) {
      LOG_WARN("s is zero\n");
      continue;
    }
    if(*result != PKA_STATUS_SUCCESS) {
      LOG_ERR("Line: %u Error: %u\n", __LINE__, *result);
      PT_EXIT(protothreads);
    }
    break;
  }

  scalar_from_pka_ram(signature, r_offset);
  scalar_from_pka_ram(signature + ECC_BYTES, s_offset);
  *result = PKA_STATUS_SUCCESS;

  PT_END(protothreads);
}
/*---------------------------------------------------------------------------*/
static PT_THREAD(verify(
    const uint8_t signature[static ECC_SIGNATURE_LEN],
    const uint8_t message_hash[static ECC_BYTES],
    const uint8_t public_key[static ECC_BYTES * 2],
    int *result))
{
  static const uintptr_t e_offset =
      variables_offset;
  static const uintptr_t r_offset =
      PKA_NEXT_OFFSET(e_offset, SCALAR_SPACE);
  static const uintptr_t s_offset =
      PKA_NEXT_OFFSET(r_offset, SCALAR_SPACE);
  static const uintptr_t q_offset =
      PKA_NEXT_OFFSET(s_offset, SCALAR_SPACE);
  static const uintptr_t u1_offset =
      PKA_NEXT_OFFSET(q_offset, POINT_SPACE);
  static const uintptr_t u2_offset =
      PKA_NEXT_OFFSET(u1_offset, MAX(REMAINDER_SPACE, COORDINATE_SPACE));
  static const uintptr_t p1_offset =
      PKA_NEXT_OFFSET(u2_offset, MAX(REMAINDER_SPACE, COORDINATE_SPACE));
  static const uintptr_t p2_offset =
      PKA_NEXT_OFFSET(p1_offset, POINT_SPACE);
  /* PKA_NEXT_OFFSET(p2_offset, POINT_SPACE); */

  PT_BEGIN(protothreads);

  /* copy inputs to PKA RAM */
  scalar_to_pka_ram(public_key, q_offset);
  scalar_to_pka_ram(public_key + ECC_BYTES, q_offset + COORDINATE_SPACE);
  scalar_to_pka_ram(signature, r_offset);
  scalar_to_pka_ram(signature + ECC_BYTES, s_offset);
  scalar_to_pka_ram(message_hash, e_offset);

  /* ensure that 0 < r < n */
  PT_SPAWN(protothreads,
      protothreads + 1,
      check_bounds(r_offset,
          null_scalar_offset,
          curve_n_offset,
          result));
  if(*result != PKA_STATUS_SUCCESS) {
    LOG_ERR("Line: %u Error: %u\n", __LINE__, *result);
    PT_EXIT(protothreads);
  }

  /* ensure that 0 < s < n */
  PT_SPAWN(protothreads,
      protothreads + 1,
      check_bounds(s_offset,
          null_scalar_offset,
          curve_n_offset,
          result));
  if(*result != PKA_STATUS_SUCCESS) {
    LOG_ERR("Line: %u Error: %u\n", __LINE__, *result);
    PT_EXIT(protothreads);
  }

  /* s := 1 / s */
  PT_SPAWN(protothreads,
      protothreads + 1,
      invert_modulo(s_offset, curve_n_offset, s_offset, result));
  if(*result != PKA_STATUS_SUCCESS) {
    LOG_ERR("Line: %u Error: %u\n", __LINE__, *result);
    PT_EXIT(protothreads);
  }

  /* u1 := e / s mod n */
  PT_SPAWN(protothreads,
      protothreads + 1,
      add_or_multiply_modulo(PKA_FUNCTION_MULTIPLY,
          s_offset,
          e_offset,
          curve_n_offset,
          u1_offset,
          result));
  if(*result != PKA_STATUS_SUCCESS) {
    LOG_ERR("Line: %u Error: %u\n", __LINE__, *result);
    PT_EXIT(protothreads);
  }

  /* p1 := u1 x G */
  PT_SPAWN(protothreads,
      protothreads + 1,
      add_or_multiply_point(PKA_FUNCTION_ECCMUL,
          u1_offset,
          curve_g_offset,
          p1_offset,
          result));
  if(*result != PKA_STATUS_SUCCESS) {
    LOG_ERR("Line: %u Error: %u\n", __LINE__, *result);
    PT_EXIT(protothreads);
  }

  /* u2 := r / s mod n */
  PT_SPAWN(protothreads,
      protothreads + 1,
      add_or_multiply_modulo(PKA_FUNCTION_MULTIPLY,
          s_offset,
          r_offset,
          curve_n_offset,
          u2_offset,
          result));
  if(*result != PKA_STATUS_SUCCESS) {
    LOG_ERR("Line: %u Error: %u\n", __LINE__, *result);
    PT_EXIT(protothreads);
  }

  /* p2 := u2 x Q */
  PT_SPAWN(protothreads,
      protothreads + 1,
      add_or_multiply_point(PKA_FUNCTION_ECCMUL,
          u2_offset,
          q_offset,
          p2_offset,
          result));
  if(*result != PKA_STATUS_SUCCESS) {
    LOG_ERR("Line: %u Error: %u\n", __LINE__, *result);
    PT_EXIT(protothreads);
  }

  /* p := p1 + p2 */
  PT_SPAWN(protothreads,
      protothreads + 1,
      add_or_multiply_point(PKA_FUNCTION_ECCADD,
          p1_offset,
          p2_offset,
          p1_offset,
          result));
  if(*result != PKA_STATUS_SUCCESS) {
    LOG_ERR("Line: %u Error: %u\n", __LINE__, *result);
    PT_EXIT(protothreads);
  }

  /* verify */
  PT_SPAWN(protothreads,
      protothreads + 1,
      compare_a_and_b(p1_offset, r_offset, result));
  if(*result != PKA_STATUS_A_EQ_B) {
    LOG_ERR("Line: %u Error: %u\n", __LINE__, *result);
    PT_EXIT(protothreads);
  }
  *result = PKA_STATUS_SUCCESS;

  PT_END(protothreads);
}
/*---------------------------------------------------------------------------*/
static PT_THREAD(generate_key_pair(
    uint8_t private_key[static ECC_BYTES],
    uint8_t public_key[static ECC_BYTES * 2],
    int *result))
{
  static const uintptr_t private_key_offset =
      variables_offset;
  static const uintptr_t public_key_offset =
      PKA_NEXT_OFFSET(private_key_offset, COORDINATE_SPACE);
  /* PKA_NEXT_OFFSET(public_key_offset, POINT_SPACE); */

  PT_BEGIN(protothreads);

  while(1) {
    /* generate private key */
    if(!csprng_rand(private_key, ECC_BYTES)) {
      LOG_ERR("CSPRNG error\n");
      *result = PKA_STATUS_FAILURE;
      PT_EXIT(protothreads);
    }
    scalar_to_pka_ram(private_key, private_key_offset);
    PT_SPAWN(protothreads,
        protothreads + 1,
        check_bounds(private_key_offset,
            null_scalar_offset,
            curve_n_offset,
            result));
    if(*result != PKA_STATUS_SUCCESS) {
      LOG_WARN("private key was not in [1, n-1]\n");
      continue;
    }

    /* generate public key */
    PT_SPAWN(protothreads,
        protothreads + 1,
        add_or_multiply_point(PKA_FUNCTION_ECCMUL,
            private_key_offset,
            curve_g_offset,
            public_key_offset,
            result));
    if(*result == PKA_SHIFT_POINT_AT_INFINITY) {
      LOG_WARN("public key at infinity\n");
      continue;
    }
    if(*result != PKA_STATUS_SUCCESS) {
      LOG_ERR("Line: %u Error: %u\n", __LINE__, *result);
      PT_EXIT(protothreads);
    }
    break;
  }

  scalar_from_pka_ram(public_key, public_key_offset);
  scalar_from_pka_ram(public_key + ECC_BYTES,
      public_key_offset + COORDINATE_SPACE);

  PT_END(protothreads);
}
/*---------------------------------------------------------------------------*/
static PT_THREAD(generate_shared_secret(
    const uint8_t private_key[static ECC_BYTES],
    const uint8_t public_key[static ECC_BYTES * 2],
    uint8_t shared_secret[static ECC_BYTES],
    int *result))
{
  static const uintptr_t private_key_offset =
      variables_offset;
  static const uintptr_t public_key_offset =
      PKA_NEXT_OFFSET(private_key_offset, SCALAR_SPACE);
  static const uintptr_t product_offset =
      PKA_NEXT_OFFSET(public_key_offset, POINT_SPACE);
  /* PKA_NEXT_OFFSET(product_offset, POINT_SPACE); */

  PT_BEGIN(protothreads);

  /* copy inputs to PKA RAM */
  scalar_to_pka_ram(private_key, private_key_offset);
  scalar_to_pka_ram(public_key, public_key_offset);
  scalar_to_pka_ram(public_key + ECC_BYTES,
      public_key_offset + COORDINATE_SPACE);

  /* do ECDH */
  PT_SPAWN(protothreads,
      protothreads + 1,
      add_or_multiply_point(PKA_FUNCTION_ECCMUL,
          private_key_offset,
          public_key_offset,
          product_offset,
          result));
  if(*result == PKA_STATUS_FAILURE) {
    LOG_ERR("Line: %u Error: %u\n", __LINE__, *result);
    PT_EXIT(protothreads);
  }
  scalar_from_pka_ram(shared_secret, product_offset);
  *result = PKA_STATUS_SUCCESS;

  PT_END(protothreads);
}
/*---------------------------------------------------------------------------*/
static PT_THREAD(generate_fhmqv_secret(
    uint8_t shared_secret[static ECC_BYTES],
    const uint8_t static_private_key[static ECC_BYTES],
    const uint8_t ephemeral_private_key[static ECC_BYTES],
    const uint8_t static_public_key[static ECC_BYTES * 2],
    const uint8_t ephemeral_public_key[static ECC_BYTES * 2],
    const uint8_t d[static ECC_BYTES],
    const uint8_t e[static ECC_BYTES],
    int *result))
{
  static const uintptr_t static_private_key_offset =
      variables_offset;
  static const uintptr_t ephemeral_private_key_offset =
      PKA_NEXT_OFFSET(static_private_key_offset, SCALAR_SPACE);
  static const uintptr_t static_public_key_offset =
      PKA_NEXT_OFFSET(ephemeral_private_key_offset, SCALAR_SPACE);
  static const uintptr_t ephemeral_public_key_offset =
      PKA_NEXT_OFFSET(static_public_key_offset, POINT_SPACE);
  static const uintptr_t d_offset =
      PKA_NEXT_OFFSET(ephemeral_public_key_offset, POINT_SPACE);
  static const uintptr_t e_offset =
      PKA_NEXT_OFFSET(d_offset, SCALAR_SPACE);
  static const uintptr_t s_offset =
      PKA_NEXT_OFFSET(e_offset, SCALAR_SPACE);
  static const uintptr_t sigma_offset =
      PKA_NEXT_OFFSET(s_offset, SCALAR_SPACE);
  /* PKA_NEXT_OFFSET(sigma_offset, POINT_SPACE); */

  PT_BEGIN(protothreads);

  /* copy inputs to PKA RAM */
  scalar_to_pka_ram(static_private_key, static_private_key_offset);
  scalar_to_pka_ram(ephemeral_private_key, ephemeral_private_key_offset);
  scalar_to_pka_ram(static_public_key, static_public_key_offset);
  scalar_to_pka_ram(static_public_key + ECC_BYTES,
      static_public_key_offset + COORDINATE_SPACE);
  scalar_to_pka_ram(ephemeral_public_key, ephemeral_public_key_offset);
  scalar_to_pka_ram(ephemeral_public_key + ECC_BYTES,
      ephemeral_public_key_offset + COORDINATE_SPACE);
  scalar_to_pka_ram(d, d_offset);
  scalar_to_pka_ram(e, e_offset);

  /* s := d * static private key */
  PT_SPAWN(protothreads,
      protothreads + 1,
      add_or_multiply_modulo(PKA_FUNCTION_MULTIPLY,
          d_offset,
          static_private_key_offset,
          curve_n_offset,
          s_offset,
          result));
  if(*result != PKA_STATUS_SUCCESS) {
    LOG_ERR("Line: %u Error: %u\n", __LINE__, *result);
    PT_EXIT(protothreads);
  }

  /* s := ephemeral private key + d * static private key */
  PT_SPAWN(protothreads,
      protothreads + 1,
      add_or_multiply_modulo(PKA_FUNCTION_ADD,
          s_offset,
          ephemeral_private_key_offset,
          curve_n_offset,
          s_offset,
          result));
  if(*result != PKA_STATUS_SUCCESS) {
    LOG_ERR("Line: %u Error: %u\n", __LINE__, *result);
    PT_EXIT(protothreads);
  }

  /* sigma := e x static public key */
  PT_SPAWN(protothreads,
      protothreads + 1,
      add_or_multiply_point(PKA_FUNCTION_ECCMUL,
          e_offset,
          static_public_key_offset,
          sigma_offset,
          result));
  if(*result != PKA_STATUS_SUCCESS) {
    LOG_ERR("Line: %u Error: %u\n", __LINE__, *result);
    PT_EXIT(protothreads);
  }

  /* sigma := ephemeral public key + e x static public key */
  PT_SPAWN(protothreads,
      protothreads + 1,
      add_or_multiply_point(PKA_FUNCTION_ECCADD,
          sigma_offset,
          ephemeral_public_key_offset,
          sigma_offset,
          result));
  if(*result != PKA_STATUS_SUCCESS) {
    LOG_ERR("Line: %u Error: %u\n", __LINE__, *result);
    PT_EXIT(protothreads);
  }

  /* sigma := s x (ephemeral public key + e x static public key) */
  PT_SPAWN(protothreads,
      protothreads + 1,
      add_or_multiply_point(PKA_FUNCTION_ECCMUL,
          s_offset,
          sigma_offset,
          sigma_offset,
          result));
  if(*result != PKA_STATUS_SUCCESS) {
    LOG_ERR("Line: %u Error: %u\n", __LINE__, *result);
    PT_EXIT(protothreads);
  }

  scalar_from_pka_ram(shared_secret, sigma_offset);
  *result = PKA_STATUS_SUCCESS;

  PT_END(protothreads);
}
/*---------------------------------------------------------------------------*/
static void
disable(void)
{
  pka_disable();
}
/*---------------------------------------------------------------------------*/
const struct ecc_driver cc2538_ecc_driver = {
  enable,
  get_protothread,
  validate_public_key,
  compress_public_key,
  decompress_public_key,
  sign,
  verify,
  generate_key_pair,
  generate_shared_secret,
  generate_fhmqv_secret,
  disable
};
/*---------------------------------------------------------------------------*/
/**
 * @}
 */
