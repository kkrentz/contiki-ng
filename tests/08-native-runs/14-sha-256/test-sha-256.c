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
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDER AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "contiki.h"
#include "unit-test.h"
#include "lib/sha-256.h"
#include "lib/hexconv.h"
#include <stddef.h>
#include <string.h>
#include <stdio.h>

PROCESS(test_process, "test");
AUTOSTART_PROCESSES(&test_process);

static const struct {
  const char *data[3];
  uint8_t hash[SHA_256_DIGEST_LENGTH];
} hashes[] = {
  { /* Simple */
    {
      "abc",
      NULL,
      NULL
    }, {
      0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
      0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
      0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
      0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad
    }
  }, { /* Simple */
    {
      "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
      NULL,
      NULL,
    }, {
      0x24, 0x8d, 0x6a, 0x61, 0xd2, 0x06, 0x38, 0xb8,
      0xe5, 0xc0, 0x26, 0x93, 0x0c, 0x3e, 0x60, 0x39,
      0xa3, 0x3c, 0xe4, 0x59, 0x64, 0xff, 0x21, 0x67,
      0xf6, 0xec, 0xed, 0xd4, 0x19, 0xdb, 0x06, 0xc1
    }
  }, { /* Message of length 130 */
    {
      "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklabcd"
      "efghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmn",
      NULL,
      NULL
    }, {
      0x15, 0xd2, 0x3e, 0xea, 0x57, 0xb3, 0xd4, 0x61,
      0xbf, 0x38, 0x91, 0x12, 0xab, 0x4c, 0x43, 0xce,
      0x85, 0xe1, 0x68, 0x23, 0x8a, 0xaa, 0x54, 0x8e,
      0xc8, 0x6f, 0x0c, 0x9d, 0x65, 0xf9, 0xb9, 0x23
    }
  }, { /* Message of length 128 */
    {
      "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklabcd"
      "efghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijkl",
      NULL,
      NULL
    }, {
      0xf8, 0xa3, 0xf2, 0x26, 0xfc, 0x42, 0x10, 0xe9,
      0x0d, 0x13, 0x0c, 0x7f, 0x41, 0xf2, 0xbe, 0x66,
      0x45, 0x53, 0x85, 0xd2, 0x92, 0x0a, 0xda, 0x78,
      0x15, 0xf8, 0xf7, 0x95, 0xd9, 0x44, 0x90, 0x5f
    }
  }, { /* Message of length 64 */
    {
      "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijkl",
      NULL,
      NULL
    }, {
      0x2f, 0xcd, 0x5a, 0x0d, 0x60, 0xe4, 0xc9, 0x41,
      0x38, 0x1f, 0xcc, 0x4e, 0x00, 0xa4, 0xbf, 0x8b,
      0xe4, 0x22, 0xc3, 0xdd, 0xfa, 0xfb, 0x93, 0xc8,
      0x09, 0xe8, 0xd1, 0xe2, 0xbf, 0xff, 0xae, 0x8e
    }
  }, { /* Message of length 66 */
    {
      "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmn",
      NULL,
      NULL
    }, {
      0x92, 0x90, 0x1c, 0x85, 0x82, 0xe3, 0x1c, 0x05,
      0x69, 0xb5, 0x36, 0x26, 0x9c, 0xe2, 0x2c, 0xc8,
      0x30, 0x8b, 0xa4, 0x17, 0xab, 0x36, 0xc1, 0xbb,
      0xaf, 0x08, 0x4f, 0xf5, 0x8b, 0x18, 0xdc, 0x6a
    }
  }, {
    {
      "abcdbcdecdefde",
      "fgefghfghighijhijkijkljklmklmnlmnomnopnopq",
      NULL
    }, {
      0x24, 0x8d, 0x6a, 0x61, 0xd2, 0x06, 0x38, 0xb8,
      0xe5, 0xc0, 0x26, 0x93, 0x0c, 0x3e, 0x60, 0x39,
      0xa3, 0x3c, 0xe4, 0x59, 0x64, 0xff, 0x21, 0x67,
      0xf6, 0xec, 0xed, 0xd4, 0x19, 0xdb, 0x06, 0xc1
    }
  }, {
    {
      "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijkl",
      "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijkl",
      NULL
    }, {
      0xf8, 0xa3, 0xf2, 0x26, 0xfc, 0x42, 0x10, 0xe9,
      0x0d, 0x13, 0x0c, 0x7f, 0x41, 0xf2, 0xbe, 0x66,
      0x45, 0x53, 0x85, 0xd2, 0x92, 0x0a, 0xda, 0x78,
      0x15, 0xf8, 0xf7, 0x95, 0xd9, 0x44, 0x90, 0x5f
    }
  }, {
    {
      "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefgh",
      "ijkl",
      "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijkl"
    }, {
      0xf8, 0xa3, 0xf2, 0x26, 0xfc, 0x42, 0x10, 0xe9,
      0x0d, 0x13, 0x0c, 0x7f, 0x41, 0xf2, 0xbe, 0x66,
      0x45, 0x53, 0x85, 0xd2, 0x92, 0x0a, 0xda, 0x78,
      0x15, 0xf8, 0xf7, 0x95, 0xd9, 0x44, 0x90, 0x5f
    }
  }, { /* empty string */
    {
      "",
      NULL,
      NULL
    }, {
      0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
      0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
      0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
      0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55
    }
  }
};
static const struct {
  uint8_t key[SHA_256_BLOCK_SIZE];
  uint8_t keylen;
  uint8_t data[SHA_256_BLOCK_SIZE];
  uint32_t datalen;
  uint8_t hmac[SHA_256_DIGEST_LENGTH];
} hmacs[] = {
  {
    {
      0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
      0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
      0x0b, 0x0b, 0x0b, 0x0b
    },
    20,
    {
      0x48, 0x69, 0x20, 0x54, 0x68, 0x65, 0x72, 0x65
    },
    8,
    {
      0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53,
      0x5c, 0xa8, 0xaf, 0xce, 0xaf, 0x0b, 0xf1, 0x2b,
      0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83, 0x3d, 0xa7,
      0x26, 0xe9, 0x37, 0x6c, 0x2e, 0x32, 0xcf, 0xf7
    }
  }
};
static const struct {
  uint8_t salt[128];
  uint32_t salt_len;
  uint8_t ikm[128];
  uint32_t ikm_len;
  uint8_t info[128];
  uint32_t info_len;
  uint8_t prk[SHA_256_DIGEST_LENGTH];
  uint8_t okm[128];
  uint16_t okm_len;
} keys[] = {
  {
    {
      0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
      0x08, 0x09, 0x0a, 0x0b, 0x0c
    },
    13,
    {
      0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
      0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
      0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b
    },
    22,
    {
      0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
      0xf8, 0xf9
    },
    10,
    {
      0x07, 0x77, 0x09, 0x36, 0x2c, 0x2e, 0x32, 0xdf,
      0x0d, 0xdc, 0x3f, 0x0d, 0xc4, 0x7b, 0xba, 0x63,
      0x90, 0xb6, 0xc7, 0x3b, 0xb5, 0x0f, 0x9c, 0x31,
      0x22, 0xec, 0x84, 0x4a, 0xd7, 0xc2, 0xb3, 0xe5
    },
    {
      0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a,
      0x90, 0x43, 0x4f, 0x64, 0xd0, 0x36, 0x2f, 0x2a,
      0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a, 0x5a, 0x4c,
      0x5d, 0xb0, 0x2d, 0x56, 0xec, 0xc4, 0xc5, 0xbf,
      0x34, 0x00, 0x72, 0x08, 0xd5, 0xb8, 0x87, 0x18,
      0x58, 0x65
    },
    42
  },
  {
    {
      0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67,
      0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f,
      0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77,
      0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f,
      0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
      0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
      0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
      0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f,
      0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7,
      0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf
    },
    80,
    {
      0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
      0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
      0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
      0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
      0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
      0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
      0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
      0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
      0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
      0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f
    },
    80,
    {
      0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7,
      0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf,
      0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,
      0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf,
      0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7,
      0xd8, 0xd9, 0xda, 0xdb, 0xdc, 0xdd, 0xde, 0xdf,
      0xe0, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7,
      0xe8, 0xe9, 0xea, 0xeb, 0xec, 0xed, 0xee, 0xef,
      0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
      0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff
    },
    80,
    {
      0x06, 0xa6, 0xb8, 0x8c, 0x58, 0x53, 0x36, 0x1a,
      0x06, 0x10, 0x4c, 0x9c, 0xeb, 0x35, 0xb4, 0x5c,
      0xef, 0x76, 0x00, 0x14, 0x90, 0x46, 0x71, 0x01,
      0x4a, 0x19, 0x3f, 0x40, 0xc1, 0x5f, 0xc2, 0x44
    },
    {
      0xb1, 0x1e, 0x39, 0x8d, 0xc8, 0x03, 0x27, 0xa1,
      0xc8, 0xe7, 0xf7, 0x8c, 0x59, 0x6a, 0x49, 0x34,
      0x4f, 0x01, 0x2e, 0xda, 0x2d, 0x4e, 0xfa, 0xd8,
      0xa0, 0x50, 0xcc, 0x4c, 0x19, 0xaf, 0xa9, 0x7c,
      0x59, 0x04, 0x5a, 0x99, 0xca, 0xc7, 0x82, 0x72,
      0x71, 0xcb, 0x41, 0xc6, 0x5e, 0x59, 0x0e, 0x09,
      0xda, 0x32, 0x75, 0x60, 0x0c, 0x2f, 0x09, 0xb8,
      0x36, 0x77, 0x93, 0xa9, 0xac, 0xa3, 0xdb, 0x71,
      0xcc, 0x30, 0xc5, 0x81, 0x79, 0xec, 0x3e, 0x87,
      0xc1, 0x4c, 0x01, 0xd5, 0xc1, 0xf3, 0x43, 0x4f,
      0x1d, 0x87
    },
    82
  },
  {
    {},
    0,
    {
      0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
      0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
      0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b
    },
    22,
    {},
    0,
    {
      0x19, 0xef, 0x24, 0xa3, 0x2c, 0x71, 0x7b, 0x16,
      0x7f, 0x33, 0xa9, 0x1d, 0x6f, 0x64, 0x8b, 0xdf,
      0x96, 0x59, 0x67, 0x76, 0xaf, 0xdb, 0x63, 0x77,
      0xac, 0x43, 0x4c, 0x1c, 0x29, 0x3c, 0xcb, 0x04
    },
    {
      0x8d, 0xa4, 0xe7, 0x75, 0xa5, 0x63, 0xc1, 0x8f,
      0x71, 0x5f, 0x80, 0x2a, 0x06, 0x3c, 0x5a, 0x31,
      0xb8, 0xa1, 0x1f, 0x5c, 0x5e, 0xe1, 0x87, 0x9e,
      0xc3, 0x45, 0x4e, 0x5f, 0x3c, 0x73, 0x8d, 0x2d,
      0x9d, 0x20, 0x13, 0x95, 0xfa, 0xa4, 0xb6, 0x1a,
      0x96, 0xc8
    },
    42
  }
};

/*---------------------------------------------------------------------------*/
UNIT_TEST_REGISTER(sha_256_hash_stepwise, "SHA-256 stepwise hashing");
UNIT_TEST(sha_256_hash_stepwise)
{
  UNIT_TEST_BEGIN();

  for(size_t i = 0; i < sizeof(hashes) / sizeof(hashes[0]); i++) {
    SHA_256.init();
    for(size_t j = 0;
        j < sizeof(hashes[i].data) / sizeof(hashes[i].data[0]);
        j++) {
      if(!hashes[i].data[j]) {
        continue;
      }
      SHA_256.update((const uint8_t *)hashes[i].data[j],
                     strlen(hashes[i].data[j]));
    }
    uint8_t digest[SHA_256_DIGEST_LENGTH];
    SHA_256.finalize(digest);
    UNIT_TEST_ASSERT(!memcmp(digest, hashes[i].hash, sizeof(digest)));
  }

  UNIT_TEST_END();
}
/*---------------------------------------------------------------------------*/
UNIT_TEST_REGISTER(sha_256_hash_with_checkpoint, "SHA-256 with checkpoint");
UNIT_TEST(sha_256_hash_with_checkpoint)
{
  UNIT_TEST_BEGIN();

  for(size_t i = 0; i < sizeof(hashes) / sizeof(hashes[0]); i++) {
    SHA_256.init();
    sha_256_checkpoint_t checkpoint;
    SHA_256.create_checkpoint(&checkpoint);
    for(size_t j = 0;
        j < sizeof(hashes[i].data) / sizeof(hashes[i].data[0]);
        j++) {
      SHA_256.restore_checkpoint(&checkpoint);
      if(!hashes[i].data[j]) {
        continue;
      }
      SHA_256.update((const uint8_t *)hashes[i].data[j],
                     strlen(hashes[i].data[j]));
      SHA_256.create_checkpoint(&checkpoint);
    }
    uint8_t sha256[SHA_256_DIGEST_LENGTH];
    SHA_256.finalize(sha256);
    UNIT_TEST_ASSERT(!memcmp(sha256, hashes[i].hash, sizeof(sha256)));
  }

  UNIT_TEST_END();
}
/*---------------------------------------------------------------------------*/
UNIT_TEST_REGISTER(sha_256_hash_shorthand, "SHA-256 hash shorthand");
UNIT_TEST(sha_256_hash_shorthand)
{
  UNIT_TEST_BEGIN();

  for(size_t i = 0; i < sizeof(hashes) / sizeof(hashes[0]); i++) {
    uint8_t buf[256];
    size_t buf_len = 0;
    for(size_t j = 0;
        j < sizeof(hashes[i].data) / sizeof(hashes[i].data[0]);
        j++) {
      if(!hashes[i].data[j]) {
        continue;
      }
      memcpy(buf + buf_len, hashes[i].data[j], strlen(hashes[i].data[j]));
      buf_len += strlen(hashes[i].data[j]);
    }
    uint8_t digest[SHA_256_DIGEST_LENGTH];
    SHA_256.hash(buf, buf_len, digest);
    UNIT_TEST_ASSERT(!memcmp(digest, hashes[i].hash, sizeof(digest)));
  }

  UNIT_TEST_END();
}
/*---------------------------------------------------------------------------*/
UNIT_TEST_REGISTER(sha_256_hmac, "SHA-256 HMAC");
UNIT_TEST(sha_256_hmac)
{
  UNIT_TEST_BEGIN();

  for(size_t i = 0; i < sizeof(hmacs) / sizeof(hmacs[0]); i++) {
    uint8_t hmac[SHA_256_DIGEST_LENGTH];
    sha_256_hmac((uint8_t *)hmacs[i].key, hmacs[i].keylen,
                 hmacs[i].data, hmacs[i].datalen,
                 hmac);
    UNIT_TEST_ASSERT(!memcmp(hmac, hmacs[i].hmac, sizeof(hmac)));
  }

  UNIT_TEST_END();
}
/*---------------------------------------------------------------------------*/
UNIT_TEST_REGISTER(sha_256_hkdf, "SHA-256 HKDF");
UNIT_TEST(sha_256_hkdf)
{
  UNIT_TEST_BEGIN();

  for(size_t i = 0; i < sizeof(keys) / sizeof(keys[0]); i++) {
    uint8_t prk[SHA_256_DIGEST_LENGTH];
    sha_256_hkdf_extract(keys[i].salt, keys[i].salt_len,
                         keys[i].ikm, keys[i].ikm_len,
                         prk);
    UNIT_TEST_ASSERT(!memcmp(prk, keys[i].prk, sizeof(prk)));
    uint8_t okm[128];
    sha_256_hkdf_expand(prk, sizeof(prk),
                        keys[i].info, keys[i].info_len,
                        okm, keys[i].okm_len);
    UNIT_TEST_ASSERT(!memcmp(okm, keys[i].okm, keys[i].okm_len));
  }

  UNIT_TEST_END();
}
/*---------------------------------------------------------------------------*/
PROCESS_THREAD(test_process, ev, data)
{
  PROCESS_BEGIN();

  printf("Run unit-test\n");
  printf("---\n");

  UNIT_TEST_RUN(sha_256_hash_stepwise);
  UNIT_TEST_RUN(sha_256_hash_with_checkpoint);
  UNIT_TEST_RUN(sha_256_hash_shorthand);
  UNIT_TEST_RUN(sha_256_hmac);
  UNIT_TEST_RUN(sha_256_hkdf);

  if(!UNIT_TEST_PASSED(sha_256_hash_stepwise)
     || !UNIT_TEST_PASSED(sha_256_hash_with_checkpoint)
     || !UNIT_TEST_PASSED(sha_256_hash_shorthand)
     || !UNIT_TEST_PASSED(sha_256_hmac)
     || !UNIT_TEST_PASSED(sha_256_hkdf)) {
    printf("=check-me= FAILED\n");
    printf("---\n");
  }

  printf("=check-me= DONE\n");
  printf("---\n");

  PROCESS_END();
}
/*---------------------------------------------------------------------------*/
