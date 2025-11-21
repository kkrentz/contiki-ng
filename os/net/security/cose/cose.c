/*
 * Copyright (c) 2024, RISE Research Institutes of Sweden AB
 * Copyright (c) 2020, Industrial Systems Institute (ISI), Patras, Greece
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
 * 3. Neither the name of the copyright holder nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */

/**
 * \file
 *         COSE, an implementation of COSE_Encrypt0 structure from: CBOR Object Signing and Encryption (COSE) (IETF RFC8152)
 * \author
 *         Lidia Pocero <pocero@isi.gr>
 *         Peter A Jonsson
 *         Rikard Höglund
 *         Marco Tiloca
 *         Niclas Finne <niclas.finne@ri.se>
 *         Nicolas Tsiftes <nicolas.tsiftes@ri.se>
 */

#include "contiki.h"
#include "lib/memb.h"
#include "lib/ccm-star.h"
#include "lib/sha-256.h"
#include "lib/cbor.h"
#include "cose.h"
#include "uECC.h"
#include <string.h>

#include "sys/log.h"
#define LOG_MODULE "COSE"
#define LOG_LEVEL LOG_LEVEL_EDHOC

MEMB(encrypt0_storage, cose_encrypt0_t, 1);
MEMB(sign1_storage, cose_sign1_t, 1);

/*----------------------------------------------------------------------------*/
void
encrypt0_storage_init(void)
{
  memb_init(&encrypt0_storage);
}
/*----------------------------------------------------------------------------*/
cose_encrypt0_t *
cose_encrypt0_new(void)
{
  return (cose_encrypt0_t *)memb_alloc(&encrypt0_storage);
}
/*----------------------------------------------------------------------------*/
void
cose_encrypt0_finalize(cose_encrypt0_t *enc)
{
  memb_free(&encrypt0_storage, enc);
}
/*----------------------------------------------------------------------------*/
void
sign1_storage_init(void)
{
  memb_init(&sign1_storage);
}
/*----------------------------------------------------------------------------*/
cose_sign1_t *
cose_sign1_new(void)
{
  return (cose_sign1_t *)memb_alloc(&sign1_storage);
}
/*----------------------------------------------------------------------------*/
void
cose_sign1_finalize(cose_sign1_t *sign)
{
  memb_free(&sign1_storage, sign);
}
/*----------------------------------------------------------------------------*/
uint8_t
cose_encrypt0_set_key(cose_encrypt0_t *enc, uint8_t alg,
                      const uint8_t *key, uint8_t key_size,
                      const uint8_t *nonce, uint16_t nonce_size)
{
  if(key_size != cose_get_key_len(enc->alg)) {
    return 0;
  }
  if(nonce_size != cose_get_iv_len(enc->alg)) {
    return 0;
  }
  if(key_size > MAX_KEY_LEN || nonce_size > MAX_IV_LEN) {
    return 0;
  }
  enc->key_sz = key_size;
  enc->nonce_sz = nonce_size;
  memcpy(enc->key, key, key_size);
  memcpy(enc->nonce, nonce, nonce_size);
  return 1;
}
/*----------------------------------------------------------------------------*/
uint8_t
cose_sign1_set_key(cose_sign1_t *sign1, int8_t alg,
                   const uint8_t *key, uint8_t key_size)
{
  if(key_size > ECC_KEY_LEN * 2) {
    return 0;
  }

  if(alg != ES256) {
    LOG_ERR("Unknown COSE signing algorithm: %d (supported: ES256=%d, ES384=%d, EdDSA=%d)\n", alg, ES256, ES384, EDDSA);
    return 0;
  }

  sign1->key_sz = key_size;
  memcpy(sign1->key, key, key_size);
  return 1;
}
/*----------------------------------------------------------------------------*/
uint8_t
cose_encrypt0_set_content(cose_encrypt0_t *enc,
                          const uint8_t *plaintext, uint16_t plaintext_size,
                          const uint8_t *additional_data, uint8_t additional_data_size)
{
  if(plaintext_size > COSE_MAX_BUFFER) {
    return 0;
  }
  memcpy(enc->plaintext, plaintext, plaintext_size);
  memcpy(enc->external_aad, additional_data, additional_data_size);
  enc->plaintext_sz = plaintext_size;
  enc->external_aad_sz = additional_data_size;
  return 1;
}
/*----------------------------------------------------------------------------*/
uint8_t
cose_encrypt0_set_ciphertext(cose_encrypt0_t *enc, const uint8_t *ciphertext,
                             uint16_t ciphertext_size)
{
  if(ciphertext_size > MAX_CIPHER) {
    return 0;
  }
  memcpy(enc->ciphertext, ciphertext, ciphertext_size);
  enc->ciphertext_sz = ciphertext_size;
  return 1;
}
/*----------------------------------------------------------------------------*/
uint8_t
cose_sign1_set_payload(cose_sign1_t *sign1, const uint8_t *payload,
                       uint16_t payload_sz)
{
  if(payload_sz > COSE_MAX_BUFFER) {
    return 0;
  }
  memcpy(sign1->payload, payload, payload_sz);
  sign1->payload_sz = payload_sz;
  return 1;
}
/*----------------------------------------------------------------------------*/
uint8_t
cose_sign1_set_signature(cose_sign1_t *sign1, const uint8_t *signature,
                         uint16_t signature_sz)
{
  if(signature_sz > COSE_MAX_BUFFER) {
    return 0;
  }
  memcpy(sign1->signature, signature, signature_sz);
  sign1->signature_sz = signature_sz;
  return 1;
}
/*----------------------------------------------------------------------------*/
uint8_t
cose_sign1_set_external_aad(cose_sign1_t *sign1, const uint8_t *external_aad,
                            uint16_t external_aad_sz)
{
  if(external_aad_sz > COSE_MAX_BUFFER) {
    return 0;
  }
  memcpy(sign1->external_aad, external_aad, external_aad_sz);
  sign1->external_aad_sz = external_aad_sz;
  return 1;
}
/*----------------------------------------------------------------------------*/
uint8_t
cose_encrypt0_set_header(cose_encrypt0_t *enc,
                         const uint8_t *prot, uint16_t prot_sz,
                         const uint8_t *unp, uint16_t unp_sz)
{
  if(prot_sz > COSE_MAX_BUFFER || unp_sz > COSE_MAX_BUFFER) {
    LOG_ERR("COSE_Encrypt0 header size exceeds maximum: protected=%d, unprotected=%d, max=%d\n", prot_sz, unp_sz, COSE_MAX_BUFFER);
    return 0;
  }
  memcpy(enc->protected_header, prot, prot_sz);
  memcpy(enc->unprotected_header, unp, unp_sz);
  enc->protected_header_sz = prot_sz;
  enc->unprotected_header_sz = unp_sz;
  return 1;
}
/*----------------------------------------------------------------------------*/
uint8_t
cose_sign1_set_header(cose_sign1_t *sign1,
                      const uint8_t *prot, uint16_t prot_sz,
                      const uint8_t *unp, uint16_t unp_sz)
{
  if(prot_sz > COSE_MAX_BUFFER) {
    LOG_ERR("COSE_Sign1 protected header size (%d) exceeds maximum buffer size (%d)\n", prot_sz, COSE_MAX_BUFFER);
    return 0;
  }
  memcpy(sign1->protected_header, prot, prot_sz);
  /*memcpy(sign1->unprotected_header, unp, unp_sz); */
  sign1->protected_header_sz = prot_sz;
  /*sign1->unprotected_header_sz = unp_sz; */
  return 1;
}
/*----------------------------------------------------------------------------*/
static char enc_header[] = ENC0;

static uint16_t
encode_enc_structure(const cose_encrypt0_t *enc, uint8_t *cbor, size_t cbor_sz)
{
  cbor_writer_state_t writer;
  cbor_init_writer(&writer, cbor, cbor_sz);
  cbor_open_array(&writer);
  cbor_write_text(&writer, enc_header, strlen(enc_header));
  cbor_write_data(&writer, enc->protected_header, enc->protected_header_sz);
  cbor_write_data(&writer, enc->external_aad, enc->external_aad_sz);
  cbor_close_array(&writer);
  return cbor_end_writer(&writer);
}
/*----------------------------------------------------------------------------*/
static char sig_header[] = SIGN1;

static uint8_t
encode_sig_structure(const cose_sign1_t *sign1, uint8_t *cbor, size_t cbor_sz)
{
  cbor_writer_state_t writer;
  cbor_init_writer(&writer, cbor, cbor_sz);
  cbor_open_array(&writer);
  cbor_write_text(&writer, sig_header, strlen(sig_header));
  cbor_write_data(&writer, sign1->protected_header, sign1->protected_header_sz);
  cbor_write_data(&writer, sign1->external_aad, sign1->external_aad_sz);
  cbor_write_data(&writer, sign1->payload, sign1->payload_sz);
  cbor_close_array(&writer);
  return cbor_end_writer(&writer);
}
/*----------------------------------------------------------------------------*/
uint8_t
cose_encrypt0_decrypt(cose_encrypt0_t *enc)
{
  uint8_t enc_struct_bytes[COSE_MAX_BUFFER];
  uint16_t str_sz = encode_enc_structure(enc, enc_struct_bytes,
                                         sizeof(enc_struct_bytes));

  LOG_DBG("CBOR-encoded AAD for COSE_Encrypt0 decryption (%d bytes): ", str_sz);
  LOG_DBG_BYTES(enc_struct_bytes, str_sz);
  LOG_DBG_("\n");

  uint8_t key_len = cose_get_key_len(enc->alg);
  uint8_t iv_len = cose_get_iv_len(enc->alg);
  uint8_t tag_len = cose_get_tag_len(enc->alg);
  if(enc->key_sz != key_len
     || enc->nonce_sz != iv_len
     || enc->plaintext_sz > COSE_MAX_BUFFER
     || str_sz > (2 * COSE_MAX_BUFFER)
     || tag_len == 0) {
    LOG_ERR("COSE parameter mismatch: key_len=%d (expected %d), nonce_len=%d (expected %d), algorithm %d\n", enc->key_sz, key_len, enc->nonce_sz, iv_len, enc->alg);
    return 0;
  }

  uint8_t tag[tag_len];

  CCM_STAR.set_key(enc->key);
  if(enc->ciphertext_sz < tag_len) {
    LOG_ERR("COSE decryption failed: ciphertext size (%d) smaller than tag length (%d)\n", enc->ciphertext_sz, tag_len);
    return 0;
  }
  enc->plaintext_sz = enc->ciphertext_sz - tag_len;

  CCM_STAR.aead(enc->nonce, enc->ciphertext, enc->plaintext_sz, enc_struct_bytes, str_sz, tag, tag_len, 0);
  memcpy(enc->plaintext, enc->ciphertext, enc->plaintext_sz);

  /* Constant-time comparison to prevent timing attacks */
  uint8_t diff = 0;
  for(int i = 0; i < tag_len; i++) {
    diff |= (tag[i] ^ enc->ciphertext[enc->plaintext_sz + i]);
  }
  
  if(diff != 0) {
    LOG_ERR("COSE decryption failed: authentication tag verification failed\n");
    return 0;  /* Decryption failure */
  }

  return 1;
}
/*----------------------------------------------------------------------------*/
uint8_t
cose_encrypt0_encrypt(cose_encrypt0_t *enc)
{
  uint8_t enc_struct_bytes[COSE_MAX_BUFFER];
  uint16_t str_sz = encode_enc_structure(enc, enc_struct_bytes,
                                         sizeof(enc_struct_bytes));

  LOG_DBG("CBOR-encoded AAD for COSE_Encrypt0 encryption (%d bytes): ", str_sz);
  LOG_DBG_BYTES(enc_struct_bytes, str_sz);
  LOG_DBG_("\n");

  uint8_t key_len = cose_get_key_len(enc->alg);
  uint8_t iv_len = cose_get_iv_len(enc->alg);
  uint8_t tag_len = cose_get_tag_len(enc->alg);
  if(enc->key_sz != key_len || enc->nonce_sz != iv_len ||
     enc->plaintext_sz > COSE_MAX_BUFFER || str_sz > (2 * COSE_MAX_BUFFER)) {
    LOG_ERR("COSE parameter mismatch: key_len=%d (expected %d), nonce_len=%d (expected %d), algorithm %d\n", enc->key_sz, key_len, enc->nonce_sz, iv_len, enc->alg);
    return 0;
  }

  /* Set the key and copy plaintext to ciphertext buffer */
  CCM_STAR.set_key(enc->key);
  memcpy(enc->ciphertext, enc->plaintext, enc->plaintext_sz);

  /* Perform encryption */
  CCM_STAR.aead(enc->nonce, enc->ciphertext, enc->plaintext_sz, enc_struct_bytes, str_sz, &enc->ciphertext[enc->plaintext_sz], tag_len, 1);
  enc->ciphertext_sz = enc->plaintext_sz + tag_len;

  return enc->ciphertext_sz;
}
/*----------------------------------------------------------------------------*/
uint8_t
cose_sign1_sign(cose_sign1_t *sign1)
{
  uint8_t sig_struct_bytes[2 * COSE_MAX_BUFFER];
  uint8_t sig_str_sz = encode_sig_structure(sign1, sig_struct_bytes,
                                            sizeof(sig_struct_bytes));

  LOG_DBG("CBOR-encoded sig_structure for COSE_Sign1 signing (%d bytes): ",
          sig_str_sz);
  LOG_DBG_BYTES(sig_struct_bytes, sig_str_sz);
  LOG_DBG_("\n");

  LOG_DBG("Using own private key for COSE_Sign1 signing: ");
  LOG_DBG_BYTES(sign1->key, ECC_KEY_LEN);
  LOG_DBG_("\n");

  uint8_t hash[HASH_LEN];
  sha_256_hash(sig_struct_bytes, sig_str_sz, hash);

  if(uECC_sign(sign1->key, hash, sizeof(hash), sign1->signature,
               uECC_secp256r1())) {
    sign1->signature_sz = P256_SIGNATURE_LEN;
    /* LOG_DBG("Signature for COSE_Sign1 (%d bytes): ", sign1->signature_sz); */
    /* LOG_DBG_BYTES(sign1->signature, sign1->signature_sz); */
    /* LOG_DBG_("\n"); */
  } else {
    LOG_ERR("COSE_Sign1 signature generation failed for algorithm %d\n", sign1->alg);
    return 0;
  }
  return sign1->signature_sz;
}
/*----------------------------------------------------------------------------*/
uint8_t
cose_sign1_verify(cose_sign1_t *sign1)
{
  /* The other peer's public key must be in key (x concatenated with y making 64 bytes) */
  uint8_t *public_key = sign1->key;

  LOG_DBG("Using peer's public key for COSE_Sign1 signature verification: ");
  LOG_DBG_BYTES(public_key, ECC_KEY_LEN * 2);
  LOG_DBG_("\n");

  /* Recreate the sig_structure */
  uint8_t sig_struct_bytes[2 * COSE_MAX_BUFFER];
  uint8_t sig_str_sz = encode_sig_structure(sign1, sig_struct_bytes,
                                            sizeof(sig_struct_bytes));

  LOG_DBG("CBOR-encoded sig_structure for COSE_Sign1 verification (%d bytes): ",
          sig_str_sz);
  LOG_DBG_BYTES(sig_struct_bytes, sig_str_sz);
  LOG_DBG_("\n");

  uint8_t hash[HASH_LEN];
  sha_256_hash(sig_struct_bytes, sig_str_sz, hash);

  /* Verify the signature using the peer's public key */
  int verify = uECC_verify(public_key, hash, sizeof(hash), sign1->signature,
                           uECC_secp256r1());

  if(verify == 1) {
    LOG_DBG("Signature verification succeeded for COSE_Sign1\n");
    return 1;
  }

  LOG_ERR("COSE_Sign1 signature verification failed for algorithm %d\n", sign1->alg);
  return 0;
}
/*----------------------------------------------------------------------------*/
uint8_t
cose_get_key_len(uint8_t alg_id)
{
  switch(alg_id) {
  case COSE_ALG_AES_CCM_16_64_128:
    return COSE_ALG_AES_CCM_16_64_128_KEY_LEN;
  case COSE_ALG_AES_CCM_16_128_128:
    return COSE_ALG_AES_CCM_16_128_128_KEY_LEN;
  default:
    LOG_ERR("Invalid COSE algorithm %d specified\n", alg_id);
    return 0;
  }
}
/*----------------------------------------------------------------------------*/
uint8_t
cose_get_iv_len(uint8_t alg_id)
{
  switch(alg_id) {
  case COSE_ALG_AES_CCM_16_64_128:
    return COSE_ALG_AES_CCM_16_64_128_IV_LEN;
  case COSE_ALG_AES_CCM_16_128_128:
    return COSE_ALG_AES_CCM_16_128_128_IV_LEN;
  default:
    LOG_ERR("Invalid COSE algorithm %d specified\n", alg_id);
    return 0;
  }
}
/*----------------------------------------------------------------------------*/
uint8_t
cose_get_tag_len(uint8_t alg_id)
{
  switch(alg_id) {
  case COSE_ALG_AES_CCM_16_64_128:
    return COSE_ALG_AES_CCM_16_64_128_TAG_LEN;
  case COSE_ALG_AES_CCM_16_128_128:
    return COSE_ALG_AES_CCM_16_128_128_TAG_LEN;
  default:
    LOG_ERR("Invalid COSE algorithm %d specified\n", alg_id);
    return 0;
  }
}
/*----------------------------------------------------------------------------*/
