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
#include "mbedtls/sha256.h"
#include "fota.h"

#define PROCESS_MODE_VERIFY 0
#define PROCESS_MODE_INSTALL 1

#define MAX_RSA_DATA_LENGTH ((FOTA_RSA_KEY_BITSIZE/8)-(2*FOTA_SHA_HASH_BITSIZE/8)-2)

#define TRY(err) if(err) { goto CATCH; }

typedef struct {
  void* ctx;
  fota_aes_iv_t iv;
  uint32_t len;
} aes_decrypt_t;

// The model key is shared among systems of same revision and should reside in the code segment
static const char* model_id = FOTA_MODEL_ID_MK1;
static fota_aes_key_t model_key = FOTA_MODEL_KEY_MK1;

// The hmac key for verifying unencrypted package authenticity
static uint8_t hmac_key[] = FOTA_HMAC_KEY;

// Static functions
//

static inline int min(int a, int b) {
  return a<b ? a : b;
}

static int generate_random(void* ctx, uint8_t* buf, size_t len) {
  fotai_generate_random(buf, len);
  return 0;
}

static void get_public_key(mbedtls_rsa_context* key, int type) {
  fota_rsa_key_t public_key_mod;
  fotai_get_public_key(public_key_mod, type);

  mbedtls_mpi_read_binary(&key->N, public_key_mod, sizeof(fota_rsa_key_t));
  mbedtls_mpi_lset (&key->E, OPENSSL_RSA_PUBLIC_EXPONENT);
  key->len = FOTA_RSA_KEY_BITSIZE/8;
}

// The hmac is only computed on the first four pages (2x ENCC headers,
// one FWPK header and the RSA signature). This is a optimization to
// avoid reading every page twice during verification. The remaining
// pages will be verified by the RSA signature.
static int verify_hmac() {

  uint8_t storage_page[FOTA_STORAGE_PAGE_SIZE];
  mbedtls_md_context_t md_ctx;
  fota_sha_hash_t hmac_computed;
  fota_sha_hash_t hmac_embedded;
  int err, res = 0;

  mbedtls_md_init(&md_ctx);

  TRY(mbedtls_md_setup(&md_ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 1));

  TRY(mbedtls_md_hmac_starts(&md_ctx, hmac_key, sizeof(hmac_key)));

  for(int i=0; i<4; i++) {
    fotai_read_storage_page(storage_page, i);

    if(i==0) { // Copy and clear hmac from first page before updating
      memcpy(hmac_embedded, storage_page+32, sizeof(fota_sha_hash_t));
      memset(storage_page+32, 0, sizeof(fota_sha_hash_t));
    }

    TRY(mbedtls_md_hmac_update(&md_ctx, storage_page, FOTA_STORAGE_PAGE_SIZE));
  }
  TRY(mbedtls_md_hmac_finish(&md_ctx, hmac_computed));

  res = memcmp(hmac_computed, hmac_embedded, sizeof(fota_sha_hash_t))==0;

CATCH:
  mbedtls_md_free(&md_ctx);
  return res;
}

static void read_storage_page(uint8_t* buf, int page, aes_decrypt_t* decrypt_unique, aes_decrypt_t* decrypt_model) {

  uint8_t temp_buf[FOTA_STORAGE_PAGE_SIZE];
  uint8_t* b0 = buf;
  uint8_t* b1 = temp_buf;

  if(page==1) {
    b0 = temp_buf;
    b1 = buf;
  }

  fotai_read_storage_page(b0, page);

  if(page>0 && decrypt_unique) {
    fotai_aes_decrypt_block(b0, b1, FOTA_STORAGE_PAGE_SIZE, decrypt_unique->iv, decrypt_unique->ctx);
  }
  if(page>1 && decrypt_model) {
    fotai_aes_decrypt_block(b1, b0, FOTA_STORAGE_PAGE_SIZE, decrypt_model->iv, decrypt_model->ctx);
  }
}

static void decrypt_init(aes_decrypt_t* decrypt, fota_aes_key_t key, uint8_t* buf) {
  if(memcmp(buf, "ENCC", 4)==0) {
    fotai_aes_decrypt_init(key, &decrypt->ctx);
    decrypt->len = le32toh(*((uint32_t*)(buf + 4)));
    memcpy(decrypt->iv, buf+16, sizeof(fota_aes_iv_t));
  }
}

static void decrypt_free(aes_decrypt_t* decrypt) {
  fotai_aes_decrypt_free(decrypt->ctx);
}

static int process_package(int mode) {
  uint8_t storage_page[FOTA_STORAGE_PAGE_SIZE];
  aes_decrypt_t decrypt_unique, decrypt_model;
  int res = 0;

  // Get the unique key
  fota_aes_key_t unique_key;
  fotai_get_unique_key(unique_key);

  // Read unique encrypted container header
  read_storage_page(storage_page, 0, NULL, NULL);
  decrypt_init(&decrypt_unique, unique_key, storage_page);

  // Read model encrypted container header
  read_storage_page(storage_page, 1, &decrypt_unique, NULL);
  decrypt_init(&decrypt_model, model_key, storage_page);

  // Read firmware package header
  read_storage_page(storage_page, 2, &decrypt_unique, &decrypt_model);

  if(memcmp(storage_page, "FWPK", 4)==0) {

    uint32_t firmware_len = le32toh(*((uint32_t*)(storage_page+4)));

    if(strcmp((const char*)(storage_page+16), model_id)==0) {

      // Read firmware signature (must read all pages consecutively)
      read_storage_page(storage_page, 3, &decrypt_unique, &decrypt_model);

      if(mode == PROCESS_MODE_INSTALL) {
        uint8_t firmware_page_buf[FOTA_INSTALL_PAGE_SIZE];

        int storage_page_index = 4;
        int remaining = firmware_len;

        int firmware_page_offset = 0;
        int firmware_page_index = 0;
        int firmware_page_len = 0;

        while(remaining>0) {

          // Read firmware
          read_storage_page(firmware_page_buf + firmware_page_offset, storage_page_index, &decrypt_unique, &decrypt_model);

          int n = min(FOTA_STORAGE_PAGE_SIZE, remaining);
          firmware_page_len += n;

          remaining -= n;
          storage_page_index++;
          firmware_page_offset += FOTA_STORAGE_PAGE_SIZE;

          if(firmware_page_offset >= FOTA_INSTALL_PAGE_SIZE || n < FOTA_STORAGE_PAGE_SIZE) {
            fotai_write_firmware_page(firmware_page_buf, firmware_page_index++, firmware_page_len);
            firmware_page_offset = 0;
            firmware_page_len = 0;
          }
        }
        res = 1;
      }
      else {
        mbedtls_sha256_context sha_ctx;
        fota_rsa_key_t firmware_sign;
        fota_sha_hash_t firmware_hash;

        memcpy(firmware_sign, storage_page, sizeof(fota_rsa_key_t));

        mbedtls_sha256_init(&sha_ctx);
        mbedtls_sha256_starts_ret(&sha_ctx, 0);

        int page = 4;
        int remaining = firmware_len;
        while(remaining>0) {

          // Read firmware
          read_storage_page(storage_page, page, &decrypt_unique, &decrypt_model);

          int n = min(FOTA_STORAGE_PAGE_SIZE, remaining);

          mbedtls_sha256_update_ret(&sha_ctx, storage_page, n);

          remaining -= n;
          page++;
        }

        mbedtls_sha256_finish(&sha_ctx, firmware_hash);
        mbedtls_sha256_free(&sha_ctx);

        // Get the public signing key
        mbedtls_rsa_context public_key;
        mbedtls_rsa_init(&public_key, MBEDTLS_RSA_PKCS_V21, 0);
        get_public_key(&public_key, FOTA_PUBLIC_KEY_TYPE_SIGNING);

        // Verify signature
        res = !mbedtls_rsa_pkcs1_verify(&public_key, NULL, NULL, MBEDTLS_RSA_PUBLIC, MBEDTLS_MD_SHA256, 0, firmware_hash, firmware_sign);
        mbedtls_rsa_free(&public_key);
      }
    }
    else {
#ifdef FOTA_TOOL
      fprintf(stderr, "Error: Bad model id\n");
#endif
    }
  }

  decrypt_free(&decrypt_unique);
  decrypt_free(&decrypt_model);

  return res;
}

// API functions
//

const char* fota_model_id() {
  return model_id;
}

int fota_request_token(fota_token_t token) {

  // Get the unique key
  fota_aes_key_t unique_key;
  fotai_get_unique_key(unique_key);

  // Create the request token content
  uint8_t buf[MAX_RSA_DATA_LENGTH];
  memcpy(buf, model_key, sizeof(fota_aes_key_t));
  memcpy(buf+sizeof(fota_aes_key_t), unique_key, sizeof(fota_aes_key_t));

  // Add auxillary data to request token
  fotai_get_aux_request_data(buf+2*sizeof(fota_aes_key_t), MAX_RSA_DATA_LENGTH-2*sizeof(fota_aes_key_t));

  // Get the public encryption key
  mbedtls_rsa_context public_key;
  mbedtls_rsa_init(&public_key, MBEDTLS_RSA_PKCS_V21, MBEDTLS_MD_SHA256);
  get_public_key(&public_key, FOTA_PUBLIC_KEY_TYPE_ENCRYPTION);

  // Encrypt buffer
  int err = mbedtls_rsa_rsaes_oaep_encrypt(&public_key,
                                           generate_random, NULL,
                                           MBEDTLS_RSA_PUBLIC,
                                           (const unsigned char*)FOTA_RSA_OAEP_LABEL, 
                                           strlen(FOTA_RSA_OAEP_LABEL),
                                           sizeof(buf), (unsigned char*)buf,
                                           token);

  mbedtls_rsa_free(&public_key);

  return !err;
}

int fota_verify_package(void) {
  if(!verify_hmac())
    return 0;

  return process_package(PROCESS_MODE_VERIFY);
}

int fota_install_package(void) {
  return process_package(PROCESS_MODE_INSTALL);
}
