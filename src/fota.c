// MIT License
// 
// Copyright (c) 2020 Andreas Alptun
// 
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
// 
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

#ifdef FOTA_TOOL
#include <stdio.h>
#endif
#include <stdlib.h>
#include <string.h>
#include "mbedtls/rsa.h"
#include "mbedtls/sha1.h"
#include "mbedtls/aes.h"
#include "fota.h"

// TODO system random generator
extern int sprng_random(void* context, uint8_t* buffer, size_t size);

// TODO This unique key must be generated with the fota-tool and should reside in flash memory
static aes_key_t unique_key = {0xf6,0xb9,0x29,0x0d,0x46,0x4d,0xdd,0x28,0x9b,0xf9,0x11,0x4e,0xfe,0xd1,0x6d,0x50};

// This key is shared among all vehicles and should reside in the code segment
static const char* model_id = MODEL_ID_MK1;
static aes_key_t model_key = MODEL_KEY_MK1;

static void get_public_key(mbedtls_rsa_context* key, const char* mod) {
  mbedtls_mpi_read_string(&key->N, 16, mod);
  mbedtls_mpi_read_string(&key->E, 16, RSA_KEY_PUBLIC_EXP);
  key->len = RSA_KEY_BITSIZE/8;
}

static int nibble(int val) {
  unsigned int v = (val&0xf);
  return v>9 ? v-10+'a' : v+'0';
}

const char* fota_model_id() {
  return model_id;
}

char* fota_request_token() {

  buffer_t* buf = buf_alloc(2*sizeof(aes_key_t));
  buf_write(buf, model_key, sizeof(aes_key_t));
  buf_write(buf, unique_key, sizeof(aes_key_t));

  // Get the public encryption key
  mbedtls_rsa_context public_key;
  mbedtls_rsa_init(&public_key, MBEDTLS_RSA_PKCS_V21, MBEDTLS_MD_SHA1);
  get_public_key(&public_key, RSA_ENCR_KEY_MODULO);

  // Encrypt buffer
  rsa_cipher_t request_key;
  // int err = mbedtls_rsa_rsaes_pkcs1_v15_encrypt(&public_key, sprng_random, NULL, MBEDTLS_RSA_PUBLIC, buf->len, buf->data, request_key);
  int err = mbedtls_rsa_rsaes_oaep_encrypt(&public_key, sprng_random, NULL, MBEDTLS_RSA_PUBLIC, NULL, 0, buf->len, buf->data, request_key);

  free(buf);
  mbedtls_rsa_free(&public_key);

  if(err) {
    return NULL;
  }

  char* request_key_str = malloc(2*sizeof(rsa_cipher_t)+1);
  char* str = request_key_str;
  for(int i=0; i<sizeof(rsa_cipher_t); i++) {
    int b = request_key[i];
    *str++ = nibble(b>>4);
    *str++ = nibble(b);
  }
  *str = '\0';

  return request_key_str;
}

typedef struct {
  char name[8];
  uint32_t len;
  uint8_t* data;
} chunk_t;

static int next_chunk(buffer_t* buf, chunk_t* chunk) {
  int remaining = buf->len - buf->pos;

  // Buffer may be padded with zeros, no chunk
  if(remaining<8 || !*buf_ptr(buf))
    return 0;

  memcpy(chunk->name, buf_seek(buf, 4), 4);
  chunk->name[4] = 0;
  chunk->len = buf_read_uint32(buf);
  chunk->data = buf_ptr(buf);
  buf->pos += chunk->len;

  return buf->pos <= buf->len;
}

static buffer_t* aes_decrypt(buffer_t* buf, aes_key_t key) {
  char tag[4];
  memcpy(tag, buf_seek(buf, 4), 4);

  if(memcmp(tag, "ENCC", 4)==0) {
    uint32_t len = buf_read_uint32(buf);
    uint32_t len_aligned = buf_read_uint32(buf);
    buf_seek(buf, 4);

    aes_iv_t aes_iv;
    buf_read(buf, aes_iv, sizeof(aes_iv_t));

    mbedtls_aes_context aes;
    mbedtls_aes_init(&aes);
    int err = mbedtls_aes_setkey_dec(&aes, key, AES_KEY_BITSIZE);
    if(!err) {
      buffer_t* out_buf = buf_alloc(len_aligned);
      err = mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_DECRYPT, len_aligned, aes_iv, buf_ptr(buf), out_buf->data);
      mbedtls_aes_free(&aes);
      if(err) {
        free(out_buf);
      }
      else {
        out_buf->len = len;
        return out_buf;
      }
    }
  }
  return NULL;
}

buffer_t* fota_verify_package(buffer_t* fwpk_enc2_buf) {
  if(!fwpk_enc2_buf) return NULL;

  buffer_t* fwpk_enc_buf = aes_decrypt(fwpk_enc2_buf, unique_key);
  if(fwpk_enc_buf) {
    buffer_t* fwpk_buf = aes_decrypt(fwpk_enc_buf, model_key);
    free(fwpk_enc_buf);

    if(fwpk_buf && memcmp(fwpk_buf->data, "FWPK", 4)==0) {

      int has_model = 0;
      buffer_t* firmware_buf = NULL;
      rsa_sign_t firmware_sign;

      chunk_t chunk;
      while(next_chunk(fwpk_buf, &chunk)) {
        if(strcmp(chunk.name, "MODL")==0) {
          if(strcmp((const char*)chunk.data, model_id)!=0) {
            #ifdef FOTA_TOOL
            fprintf(stderr, "bad model id\n");
            #endif
            free(fwpk_buf);
            return NULL;
          }
          has_model = 1;
        }
        else if(strcmp(chunk.name, "FRMW")==0) {
          firmware_buf = buf_alloc(chunk.len);
          buf_write(firmware_buf, chunk.data, chunk.len);
        }
        else if(strcmp(chunk.name, "SIGN")==0) {
          memcpy(firmware_sign, chunk.data, sizeof(rsa_sign_t));
        }
      }
      free(fwpk_buf);

      if(!firmware_buf || !has_model) {
        #ifdef FOTA_TOOL
        fprintf(stderr, "file corrupt\n");
        #endif
        return NULL;
      }

      // Create firmware hash
      sha_hash_t firmware_hash;
      mbedtls_sha1_ret(firmware_buf->data, firmware_buf->len, firmware_hash);

      // Get the public signing key
      mbedtls_rsa_context public_key;
      mbedtls_rsa_init(&public_key, MBEDTLS_RSA_PKCS_V21, 0);
      get_public_key(&public_key, RSA_SIGN_KEY_MODULO);

      // Verify signature
      int valid = !mbedtls_rsa_pkcs1_verify(&public_key, NULL, NULL, MBEDTLS_RSA_PUBLIC, MBEDTLS_MD_SHA1, 0, firmware_hash, firmware_sign);

      mbedtls_rsa_free(&public_key);

      if(valid)
        return firmware_buf;
    }
  }

  return NULL;
}
