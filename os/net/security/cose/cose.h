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
 *         Public API declarations for COSE (RFC8152)
 * \author
 *         Lidia Pocero <pocero@isi.gr>, Rikard Höglund, Marco Tiloca
 *         Christos Koulamas <cklm@isi.gr>, Niclas Finne <niclas.finne@ri.se>,
 *         Nicolas Tsiftes <nicolas.tsiftes@ri.se>
 */

/**
 * \defgroup COSE A COSE implementation (RFC9052)
 * @{
 * This is an implementation of the CBOR Object Signing and Encryption (COSE) protocol (RFC9052)
 * for COSE_Encrypt0 and COSE_Sign1 structures. This specification describes how to create and process
 * signatures, message authentication codes, and encryption using CBOR for serialization.
 **/

#ifndef _COSE_H_
#define _COSE_H_

#include <stdint.h>
#include <stddef.h>
#include "edhoc-config.h"

/* COSE Algorithm parameters AES-CCM-16-64-128 */
#define COSE_ALG_AES_CCM_16_64_128 10
#define COSE_ALG_AES_CCM_16_64_128_KEY_LEN 16
#define COSE_ALG_AES_CCM_16_64_128_IV_LEN  13
#define COSE_ALG_AES_CCM_16_64_128_TAG_LEN  8

/* COSE Algorithm parameters AES-CCM-16-128-128 */
#define COSE_ALG_AES_CCM_16_128_128 30
#define COSE_ALG_AES_CCM_16_128_128_KEY_LEN 16
#define COSE_ALG_AES_CCM_16_128_128_IV_LEN  13
#define COSE_ALG_AES_CCM_16_128_128_TAG_LEN  16

#define MAX_IV_LEN 13
#define MAX_KEY_LEN 16

/* Algorithms for signing */
#define ES256 -7
#define EDDSA -8
#define ES384 -35

/**
 * \brief Context strings for different COSE data structures
 */
#define ENC0 "Encrypt0"
#define SIGN1 "Signature1"

/**
 * \brief Maximum buffer length for COSE operations
 */
#ifdef COSE_CONF_MAX_BUFFER
#define COSE_MAX_BUFFER COSE_CONF_MAX_BUFFER
#define MAX_CIPHER COSE_CONF_MAX_BUFFER
#else
#define COSE_MAX_BUFFER 256
/**
 * \brief Maximum ciphertext length
 */
#define MAX_CIPHER 256
#endif

/**
 * \brief COSE_Encrypt0 struct
 */
typedef struct cose_encrypt0 {
  uint8_t protected_header[COSE_MAX_BUFFER];
  uint8_t protected_header_sz;
  uint8_t unprotected_header[COSE_MAX_BUFFER];
  uint8_t unprotected_header_sz;
  uint8_t plaintext[COSE_MAX_BUFFER];
  uint16_t plaintext_sz;
  uint8_t ciphertext[MAX_CIPHER];
  uint8_t ciphertext_sz;
  uint8_t alg;
  uint8_t key[MAX_KEY_LEN];
  uint8_t key_sz;
  uint8_t nonce[MAX_IV_LEN];
  uint8_t nonce_sz;
  uint8_t external_aad[COSE_MAX_BUFFER];
  uint8_t external_aad_sz;
} cose_encrypt0_t;

/**
 * \brief COSE_Sign1 struct
 */
typedef struct cose_sign1 {
  uint8_t protected_header[COSE_MAX_BUFFER];
  uint8_t protected_header_sz;
  uint8_t payload[COSE_MAX_BUFFER];
  uint8_t payload_sz;
  uint8_t signature[P256_SIGNATURE_LEN];
  uint8_t signature_sz;
  int8_t alg;
  uint8_t key[ECC_KEY_LEN * 2];
  uint8_t key_sz;
  uint8_t external_aad[COSE_MAX_BUFFER];
  uint8_t external_aad_sz;
} cose_sign1_t;

/**
 * \brief Initialize memory storage for COSE_Encrypt0 objects
 *
 * This function must be called before using any COSE_Encrypt0 objects to
 * initialize the memory pool.
 */
void encrypt0_storage_init(void);

/**
 * \brief Initialize memory storage for COSE_Sign1 objects
 *
 * This function must be called before using any COSE_Sign1 objects to
 * initialize the memory pool.
 */
void sign1_storage_init(void);

/**
 * \brief Create a new cose_sign1 context
 * \return cose_sign1 new cose_sign1 context struct
 *
 * Used to create a new cose_sign1 object and dynamically allocate memory for it
 */
cose_sign1_t *cose_sign1_new(void);

/**
 * \brief Close the cose_sign1 context
 * \param sign cose_sign1 context struct
 *
 * Used to de-allocate the memory reserved for the cose_sign1 context
 */
void cose_sign1_finalize(cose_sign1_t *sign);

/**
 * \brief Set the protected/unprotected header information for COSE_Sign1
 * \param sign1 output cose_sign1 context
 * \param prot input protected header
 * \param prot_sz input protected header length
 * \param unp input unprotected header (unused)
 * \param unp_sz input unprotected header length (unused)
 * \return 1 if header is set successfully, 0 if header size exceeds maximum buffer
 *
 * Used before signing operation to set the protected header information.
 */
uint8_t cose_sign1_set_header(cose_sign1_t *sign1, const uint8_t *prot, uint16_t prot_sz, const uint8_t *unp, uint16_t unp_sz);

/**
 * \brief Set the payload for COSE_Sign1 signature
 * \param sign1 output cose_sign1 context
 * \param payload input The payload to be signed
 * \param payload_sz input The payload length
 * \return 1 if payload is set successfully, 0 if payload size exceeds maximum buffer
 *
 * Used before signing operation to set the payload that will be signed.
 */
uint8_t cose_sign1_set_payload(cose_sign1_t *sign1, const uint8_t *payload, uint16_t payload_sz);

/**
 * \brief Generate signature for COSE_Sign1
 * \param sign1 cose_sign1 context
 * \return signature size if signing succeeds, 0 if signing fails
 *
 * This function generates a signature using the private key and payload
 * in the COSE_Sign1 structure. The signature is stored in the signature field.
 */
uint8_t cose_sign1_sign(cose_sign1_t *sign1);

/**
 * \brief Set the signing key and algorithm for COSE_Sign1
 * \param sign1 output cose_sign1 context
 * \param alg signing algorithm identifier
 * \param key input signing key (private key for signing, public key for verification)
 * \param key_size input key length
 * \return 1 if key is set successfully, 0 if key size is invalid or algorithm unsupported
 *
 * Used before signing/verification to set the cryptographic key and algorithm.
 */
uint8_t cose_sign1_set_key(cose_sign1_t *sign1, int8_t alg, const uint8_t *key, uint8_t key_size);

/**
 * \brief Set the signature for COSE_Sign1 verification
 * \param sign1 output cose_sign1 context
 * \param signature input The signature to be verified
 * \param signature_sz input The signature length
 * \return 1 if signature is set successfully, 0 if signature size exceeds maximum buffer
 *
 * Used before verification to set the signature that will be verified.
 */
uint8_t cose_sign1_set_signature(cose_sign1_t *sign1, const uint8_t *signature, uint16_t signature_sz);

/**
 * \brief Verify signature for COSE_Sign1
 * \param sign1 cose_sign1 context
 * \return 1 if signature verification succeeds, 0 if verification fails
 *
 * This function verifies a signature using the public key and payload
 * in the COSE_Sign1 structure.
 */
uint8_t cose_sign1_verify(cose_sign1_t *sign1);

/**
 * \brief Get the key length for a COSE algorithm
 * \param alg_id COSE algorithm identifier
 * \return key length in bytes, 0 if algorithm is invalid
 *
 * Returns the required key length for the specified COSE algorithm.
 */
uint8_t cose_get_key_len(uint8_t alg_id);

/**
 * \brief Get the initialization vector length for a COSE algorithm
 * \param alg_id COSE algorithm identifier
 * \return IV length in bytes, 0 if algorithm is invalid
 *
 * Returns the required initialization vector length for the specified COSE algorithm.
 */
uint8_t cose_get_iv_len(uint8_t alg_id);

/**
 * \brief Get the authentication tag length for a COSE algorithm
 * \param alg_id COSE algorithm identifier
 * \return tag length in bytes, 0 if algorithm is invalid
 *
 * Returns the authentication tag length for the specified COSE algorithm.
 */
uint8_t cose_get_tag_len(uint8_t alg_id);

/**
 * \brief Set external additional authenticated data for COSE_Sign1
 * \param sign1 output cose_sign1 context
 * \param external_aad input external AAD
 * \param external_aad_sz input external AAD length
 * \return 1 if AAD is set successfully, 0 if AAD size exceeds maximum buffer
 *
 * Used to set external additional authenticated data that will be included
 * in the signature calculation.
 */
uint8_t cose_sign1_set_external_aad(cose_sign1_t *sign1, const uint8_t *external_aad, uint16_t external_aad_sz);

/**
 * \brief Create a new cose_encrypt0 context
 * \return cose_encrypt0 new cose_encrypt0 context struct
 *
 * Used to create a new cose_encrypt0 and allocate at the memory reserved dynamically
 */
cose_encrypt0_t *cose_encrypt0_new(void);


/**
 * \brief Close the cose_encrypt0 context
 * \param enc cose_encrypt0 context struct
 *
 * Used to de-allocate the memory reserved for the cose_encrypt0 context
 */
void cose_encrypt0_finalize(cose_encrypt0_t *enc);

/**
 * \brief Set the encryption key/nonce and the algorithm identifier on the cose_encrypt0 context
 * \param enc output cose_encrypt0 context
 * \param alg input algorithm identifier
 * \param key input pointer to the encryption/decryption key
 * \param key_size input encryption/decryption key length
 * \param nonce input pointer to the nonce (Initialization Vector (IV) value)
 * \param nonce_size input nonce length
 * \return 1 if both key and nonce have the correct length, 0 otherwise
 *
 *  Used before encryption/decryption operations to configure:
 *  - The algorithm used for security processing
 *  - The encryption key
 *  - The nonce (Initialization Vector (IV) value)
 *
 */
uint8_t cose_encrypt0_set_key(cose_encrypt0_t *enc, uint8_t alg,
                              const uint8_t *key, uint8_t key_size,
                              const uint8_t *nonce, uint16_t nonce_size);

/**
 * \brief Set the plaintext and AAD (additional authentication data) of the message
 * \param enc output cose_encrypt0 context
 * \param plaintext input The plaintext contained by the message
 * \param plaintext_size input The plaintext length
 * \param additional_data input The Additional Authentication Data
 * \param additional_data_size input The Additional Authentication Data length
 * \return 1 and the plaintext_size is smaller than the maximum buffer size
 *
 *  Used before encryption operation to select:
 *  - The plaintext or ciphertext contained by the message to encrypt
 *  - Additional Authentication Data (AAD) contained by the message
 */
uint8_t cose_encrypt0_set_content(cose_encrypt0_t *enc,
                                  const uint8_t *plaintext, uint16_t plaintext_size,
                                  const uint8_t *additional_data, uint8_t additional_data_size);

/**
 * \brief Set the ciphertext of the encrypted message
 * \param enc output cose_encrypt0 context
 * \param ciphertext input The ciphertext contained by the cipher message
 * \param ciphertext_size input The ciphertext length
 * \return 1 and the ciphertext_size is smaller than the maximum buffer size
 *
 *  Used before decryption operation to select:
 *  - The plaintext or ciphertext contained by the message to decrypt
 */
uint8_t cose_encrypt0_set_ciphertext(cose_encrypt0_t *enc,
                                     const uint8_t *ciphertext,
                                     uint16_t ciphertext_size);

/**
 * \brief Set the protected/unprotected bucket header information of the message
 * \param enc output cose_encrypt0 context
 * \param prot input protected bucket
 * \param prot_sz input protected bucket length
 * \param unp input unprotected bucket
 * \param unp_sz input unprotected bucket length
 *
 *  Used before encryption/decryption operation to select:
 *  - The protected bucket contains parameters about the current layer that are to be cryptographically protected
 *  - The unprotected bucket contains parameters about the current layer that are not cryptographically protected
 */
uint8_t cose_encrypt0_set_header(cose_encrypt0_t *enc,
                              const uint8_t *prot, uint16_t prot_sz,
                              const uint8_t *unp, uint16_t unp_sz);

/**
 * \brief  encrypt the COSE_encrypt0 struct using AEAD algorithm
 * \param enc cose_encrypt0 context
 * \return ciphertext_sz if the input parameter selected is appropriate and the cipher success and 0 otherwise
 *
 * This function implements the encryption algorithm AEAD on the data structure contained by the COSE_encrypt0 struct.
 * Before this function be called must be selected every necessary parameter of the enc (cose_encrypt0 context)
 * The ciphertext is returned in the ciphertext element of the cose_encrypt0 struct tagged by CBOR tag 16 bytes.
 *
 */
uint8_t cose_encrypt0_encrypt(cose_encrypt0_t *enc);

/**
 * \brief  decrypt the COSE_encrypt0 ciphertext using AEAD algorithm
 * \param enc cose_encrypt0 context
 * \return 1 if the TAG checking success and 0 otherwise
 *
 * This function implements the encryption algorithm AEAD on the data ciphertext element of the COSE_Encrypt0 tagged struct
 * to decrypted and check the TAG.
 * Before this function be called must be selected the ciphertext element of the enc (cose_encrypt0 context)
 * The plaintext is returned in the plaintext element of the cose_encrypt0 struct and the plaintext length in the plaintext_sz
 * element as well.
 *
 */
uint8_t cose_encrypt0_decrypt(cose_encrypt0_t *enc);

#endif /* _COSE_H_ */
/** @} */
