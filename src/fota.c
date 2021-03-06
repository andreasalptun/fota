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
#ifndef FOTA_SYSTEM_LITTLE_ENDIAN
#include <endian.h>
#endif
#include "mbedtls/rsa.h"
#include "mbedtls/sha256.h"
#include "fota.h"

#define PROCESS_MODE_VERIFY 0
#define PROCESS_MODE_INSTALL 1

#define MAX_RSA_DATA_LENGTH ((FOTA_RSA_KEY_BITSIZE/8)-(2*FOTA_SHA_HASH_BITSIZE/8)-2)

#define try(fn) { int _err = fn; if(_err) { err = _err; goto CATCH; } }
#define try_ret(fn) { int _err = fn; if(_err) { return _err; } }

typedef struct {
  fota_aes_key_t key;
  fota_aes_iv_t iv;
  uint32_t len;
  void* ctx;
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

static int get_public_key(mbedtls_rsa_context* key, int type) {
  fota_rsa_key_t public_key_mod;
  try_ret(fotai_get_public_key(public_key_mod, type));

  try_ret(mbedtls_mpi_read_binary(&key->N, public_key_mod, sizeof(fota_rsa_key_t)));
  try_ret(mbedtls_mpi_lset(&key->E, OPENSSL_RSA_PUBLIC_EXPONENT));
  key->len = FOTA_RSA_KEY_BITSIZE/8;

  return FOTA_NO_ERROR;
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
  int err = FOTA_NO_ERROR;

  mbedtls_md_init(&md_ctx);

  try(mbedtls_md_setup(&md_ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 1));

  try(mbedtls_md_hmac_starts(&md_ctx, hmac_key, sizeof(hmac_key)));

  for(int i=0; i<4; i++) {
    try(fotai_read_storage_page(storage_page, i));

    if(i==0) { // Copy and clear hmac from first page before updating
      memcpy(hmac_embedded, storage_page+32, sizeof(fota_sha_hash_t));
      memset(storage_page+32, 0, sizeof(fota_sha_hash_t));
    }

    try(mbedtls_md_hmac_update(&md_ctx, storage_page, FOTA_STORAGE_PAGE_SIZE));
  }
  try(mbedtls_md_hmac_finish(&md_ctx, hmac_computed));

  if(memcmp(hmac_computed, hmac_embedded, sizeof(fota_sha_hash_t))!=0)
    err = FOTA_ERROR_VERIFICATION_FAILED;

CATCH:
  mbedtls_md_free(&md_ctx);
  return err;
}

static int read_storage_page(uint8_t* buf, int page, aes_decrypt_t* decrypt_unique, aes_decrypt_t* decrypt_model) {

  uint8_t temp_buf[FOTA_STORAGE_PAGE_SIZE];
  uint8_t* b0 = buf;
  uint8_t* b1 = temp_buf;

  if(page==1) {
    b0 = temp_buf;
    b1 = buf;
  }

  try_ret(fotai_read_storage_page(b0, page));

  if(page>0 && decrypt_unique) {
    try_ret(fotai_aes_decrypt_block(decrypt_unique->key,
                                    b0, b1, FOTA_STORAGE_PAGE_SIZE,
                                    decrypt_unique->iv,
                                    decrypt_unique->ctx));

    // Update the initialization vector to the last 16 bytes of the input buffer
    // See https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Cipher_Block_Chaining_(CBC)
    memcpy(decrypt_unique->iv, b0+FOTA_STORAGE_PAGE_SIZE-16, 16);
  }
  if(page>1 && decrypt_model) {
    try_ret(fotai_aes_decrypt_block(decrypt_model->key,
                                    b1, b0, FOTA_STORAGE_PAGE_SIZE,
                                    decrypt_model->iv,
                                    decrypt_model->ctx));

    // Update the initialization vector to the last 16 bytes of the input buffer
    memcpy(decrypt_model->iv, b1+FOTA_STORAGE_PAGE_SIZE-16, 16);
  }

  return FOTA_NO_ERROR;
}

static int decrypt_init(aes_decrypt_t* decrypt, fota_aes_key_t key, uint8_t* buf) {

#ifdef FOTA_SYSTEM_LITTLE_ENDIAN
  decrypt->len = *((uint32_t*)(buf + 4));
#else
  decrypt->len = le32toh(*((uint32_t*)(buf + 4)));
#endif

  if(memcmp(buf, "ENCC", 4)!=0 || decrypt->len==0)
    return FOTA_ERROR_DATA_MALFORMED;

  try_ret(fotai_aes_decrypt_init(key, &decrypt->ctx));

  memcpy(decrypt->key, key, sizeof(fota_aes_key_t));
  memcpy(decrypt->iv, buf+16, sizeof(fota_aes_iv_t));

  return FOTA_NO_ERROR;
}

static void decrypt_free(aes_decrypt_t* decrypt) {

  if(decrypt->len>0)
    fotai_aes_decrypt_free(decrypt->ctx);
}

static int process_package(int mode, fota_sha_hash_t firmware_hash) {

  uint8_t storage_page[FOTA_STORAGE_PAGE_SIZE];
  aes_decrypt_t decrypt_unique = {0}, decrypt_model = {0};
  int err = FOTA_NO_ERROR;

  mbedtls_sha256_context sha_ctx;
  mbedtls_sha256_init(&sha_ctx);

  mbedtls_rsa_context public_key;
  mbedtls_rsa_init(&public_key, MBEDTLS_RSA_PKCS_V21, 0);

  // Get the unique key
  fota_aes_key_t unique_key;
  try(fotai_get_unique_key(unique_key));

  // Read unique encrypted container header
  try(read_storage_page(storage_page, 0, NULL, NULL));
  try(decrypt_init(&decrypt_unique, unique_key, storage_page));

  // Read model encrypted container header
  try(read_storage_page(storage_page, 1, &decrypt_unique, NULL));
  try(decrypt_init(&decrypt_model, model_key, storage_page));

  // Read firmware package header
  try(read_storage_page(storage_page, 2, &decrypt_unique, &decrypt_model));

  // Check header identifier
  if(memcmp(storage_page, "FWPK", 4)!=0)
    try(FOTA_ERROR_DATA_MALFORMED);

  // Check the model id
  if(strcmp((const char*)(storage_page+16), model_id)!=0)
    try(FOTA_ERROR_BAD_MODEL);

  // Get firmware length from header
#ifdef FOTA_SYSTEM_LITTLE_ENDIAN
  uint32_t firmware_len = *((uint32_t*)(storage_page+4));
#else
  uint32_t firmware_len = le32toh(*((uint32_t*)(storage_page+4)));
#endif

  // Read firmware signature (must read pages consecutively because of AES block chaining)
  try(read_storage_page(storage_page, 3, &decrypt_unique, &decrypt_model));

  int storage_page_index = 4;
  int remaining = firmware_len;

  if(mode == PROCESS_MODE_INSTALL) {
    uint8_t firmware_page_buf[FOTA_INSTALL_PAGE_SIZE];

    int firmware_page_offset = 0;
    int firmware_page_index = 0;
    int firmware_page_len = 0;

    while(remaining>0) {

      // Read and decrypt one storage page
      try(read_storage_page(firmware_page_buf + firmware_page_offset,
                            storage_page_index,
                            &decrypt_unique,
                            &decrypt_model));

      int n = min(FOTA_STORAGE_PAGE_SIZE, remaining);
      firmware_page_len += n;

      remaining -= n;
      storage_page_index++;
      firmware_page_offset += FOTA_STORAGE_PAGE_SIZE;

      // Write one firmware page
      if(firmware_page_offset >= FOTA_INSTALL_PAGE_SIZE || remaining == 0) {
        try(fotai_write_firmware_page(firmware_page_buf,
                                      firmware_page_index++,
                                      firmware_page_len));
        firmware_page_offset = 0;
        firmware_page_len = 0;
      }
    }
  }
  else { // PROCESS_MODE_VERIFY

    // Get signature from data
    fota_rsa_key_t firmware_sign;
    memcpy(firmware_sign, storage_page, sizeof(fota_rsa_key_t));

    // Calculate hash from data
    try(mbedtls_sha256_starts_ret(&sha_ctx, 0));

    while(remaining>0) {

      // Read and decrypt one storage page
      try(read_storage_page(storage_page,
                            storage_page_index,
                            &decrypt_unique,
                            &decrypt_model));

      int n = min(FOTA_STORAGE_PAGE_SIZE, remaining);

      // Update hash calculation
      try(mbedtls_sha256_update_ret(&sha_ctx, storage_page, n));

      remaining -= n;
      storage_page_index++;
    }

    // Get the final hash
    try(mbedtls_sha256_finish_ret(&sha_ctx, firmware_hash));

    // Get the public signing key
    try(get_public_key(&public_key, FOTA_PUBLIC_KEY_TYPE_SIGNING));

    // Verify signature
    try(mbedtls_rsa_pkcs1_verify(&public_key, NULL, NULL, MBEDTLS_RSA_PUBLIC, MBEDTLS_MD_SHA256, 0, firmware_hash, firmware_sign));
  }

CATCH:
  mbedtls_rsa_free(&public_key);
  mbedtls_sha256_free(&sha_ctx);

  decrypt_free(&decrypt_model);
  decrypt_free(&decrypt_unique);

  return (err==MBEDTLS_ERR_RSA_VERIFY_FAILED) ? FOTA_ERROR_VERIFICATION_FAILED : err;
}

// API functions
//

const char* fota_model_id() {
  return model_id;
}

int fota_request_token(fota_token_t token) {
  int err = FOTA_NO_ERROR;

  // Get the unique key
  fota_aes_key_t unique_key;
  try_ret(fotai_get_unique_key(unique_key));

  // Create the request token content
  uint8_t buf[MAX_RSA_DATA_LENGTH];
  memcpy(buf, model_key, sizeof(fota_aes_key_t));
  memcpy(buf+sizeof(fota_aes_key_t), unique_key, sizeof(fota_aes_key_t));

  // Add auxillary data to request token
  fotai_get_aux_request_data(buf+2*sizeof(fota_aes_key_t), MAX_RSA_DATA_LENGTH-2*sizeof(fota_aes_key_t));

  // Get the public encryption key
  mbedtls_rsa_context public_key;
  mbedtls_rsa_init(&public_key, MBEDTLS_RSA_PKCS_V21, MBEDTLS_MD_SHA256);
  try(get_public_key(&public_key, FOTA_PUBLIC_KEY_TYPE_ENCRYPTION));

  // Encrypt buffer
  try(mbedtls_rsa_rsaes_oaep_encrypt(&public_key,
                                     generate_random, NULL,
                                     MBEDTLS_RSA_PUBLIC,
                                     (const unsigned char*)FOTA_RSA_OAEP_LABEL,
                                     strlen(FOTA_RSA_OAEP_LABEL),
                                     sizeof(buf), (unsigned char*)buf,
                                     token));

CATCH:
  mbedtls_rsa_free(&public_key);

  return err;
}

int fota_verify_package(fota_sha_hash_t firmware_hash) {
  if(!firmware_hash)
    return FOTA_ERROR_BAD_ARGUMENTS;

  try_ret(verify_hmac());

  return process_package(PROCESS_MODE_VERIFY, firmware_hash);
}

int fota_install_package() {
  return process_package(PROCESS_MODE_INSTALL, NULL);
}
