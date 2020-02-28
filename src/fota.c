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

#include "fota.h"

#include <tomcrypt.h>

extern const ltc_math_descriptor tfm_desc;

// TODO This data must be unique for each vehicle and should reside in flash memory
static uuid_t vehicle_id = {0x0e,0x5d,0x97,0x81,0x5a,0xfe,0xb1,0xf2,0xe0,0x3a,0xc3,0x11,0x75,0x13,0x4a,0x18};
static aes_key_t unique_key = {0x68,0x7b,0x59,0xea,0xce,0x2d,0xda,0x48,0xab,0x2f,0xdb,0xbb,0xb5,0x19,0x1d,0x33};

// This key is shared among all vehicles and should reside in the code segment
static const char* model_id = MODEL_ID_MK1;
static aes_key_t model_key = MODEL_KEY_MK1;

static int get_public_key(rsa_key* key) {
  if(key != NULL) {

    // TODO Temporary file loader for public key, should reside in flash memory instead
    buffer_t* buf = buf_from_file(RSA_PUBLIC_KEY_FILE);

    int err = rsa_import(buf->data, buf->len, key);
    free(buf);

    if(err == CRYPT_OK) {
      return 1;
    }
  }

  return 0;
}

static int nibble(int val) {
  unsigned int v = (val&0xf);
  return v>9 ? v-10+'a' : v+'0';
}

void fota_init() {
  ltc_mp = tfm_desc;

  register_prng(&sprng_desc);
  register_hash(&sha1_desc);
  register_hash(&sha256_desc);
  register_cipher(&aes_desc);
}

const char* fota_model_id() {
  return model_id;
}

char* fota_request_key() {
  rsa_key public_key;
  if(!get_public_key(&public_key))
    return NULL;

  // TODO add vehicle_id to enable tracking

  buffer_t* buf = buf_alloc(2*sizeof(aes_key_t));
  buf_write(buf, model_key, sizeof(aes_key_t));
  buf_write(buf, unique_key, sizeof(aes_key_t));

  // Encrypt with public key
  rsa_cipher_t request_key;
  unsigned long request_key_len = sizeof(rsa_cipher_t);
  int err = rsa_encrypt_key(buf->data, buf->len,
                            request_key, &request_key_len,
                            NULL, 0,
                            NULL, find_prng("sprng"),
                            find_hash("sha1"), // nodejs only supports sha1
                            &public_key);
  free(buf);
  rsa_free(&public_key);

  if(err!=CRYPT_OK || request_key_len!=sizeof(rsa_cipher_t))
    return NULL;

  char* request_key_str = malloc(2*request_key_len+1);
  char* str = request_key_str;
  for(int i=0; i<request_key_len; i++) {
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

    symmetric_CBC cbc;
    int err = cbc_start(find_cipher("aes"), aes_iv, key, sizeof(aes_key_t), 0, &cbc);
    if(err==CRYPT_OK) {

      buffer_t* out_buf = buf_alloc(len_aligned);
      err = cbc_decrypt(buf_ptr(buf), out_buf->data, len_aligned, &cbc);
      if(err==CRYPT_OK) {
        out_buf->len = len;
        return out_buf;
      }
    }
  }
  return NULL;
}

buffer_t* fota_verify(buffer_t* fwpk_enc2_buf) {
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
            fprintf(stderr, "bad model id\n");
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
        fprintf(stderr, "file corrupt\n");
        return NULL;
      }

      // Create firmware hash
      sha_hash_t firmware_hash;
      hash_state hash;
      sha256_init(&hash);
      if(sha256_process(&hash, firmware_buf->data, firmware_buf->len)==CRYPT_OK) {
        if(sha256_done(&hash, firmware_hash)!=CRYPT_OK) {
          free(firmware_buf);
          return NULL;
        }
      }

      // Get the public key for signature validation
      rsa_key public_key;
      if(!get_public_key(&public_key))
        return NULL;

      // Check signature
      int valid;
      int err = rsa_verify_hash(firmware_sign, sizeof(rsa_sign_t),
                                firmware_hash, sizeof(sha_hash_t),
                                find_hash("sha256"),
                                8,
                                &valid,
                                &public_key);
      rsa_free(&public_key);
      
      if(err==CRYPT_OK && valid)
        return firmware_buf;
    }
  }

  return NULL;
}
