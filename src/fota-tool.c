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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <locale.h>
#include <assert.h>

#include "mbedtls/rsa.h"
#include "mbedtls/sha256.h"
#include "mbedtls/sha1.h"
#include "mbedtls/aes.h"

#define ACTION_NONE           0
#define ACTION_GENERATE_KEY   1
#define ACTION_CREATE_PACKAGE 2
#define ACTION_REQUEST_TOKEN  3
#define ACTION_VERIFY_PACKAGE 4

typedef struct {
  const char* id;
  aes_key_t key;
} model_key_t;

model_key_t model_keys[] = MODEL_KEYS;

static void print_usage() {
  printf("Usage: fota-tool [-m model] [-g generate unique keys] [-f firmware file] [-r request token] [-v verify package] [-l local mode]\n");
}

static int get_model_key(const char* model_id, aes_key_t* model_key) {
  for(int i=0; i<sizeof(model_keys)/sizeof(model_key_t); i++) {
    if(strcmp(model_keys[i].id, model_id)==0) {
      memcpy(model_key, model_keys[i].key, sizeof(aes_key_t));
      return 1;
    }
  }
  printf("model not found: %s\n", model_id);
  return 0;
}

static void write_chunk(buffer_t* buf, const char* name, const void* data, uint32_t len) {
  assert(strlen(name)==4);
  assert(buf->pos + 8 + len <= buf->len);

  buf_write(buf, name, 4);
  buf_write_uint32(buf, len);

  if(data) {
    memcpy(buf_ptr(buf), data, len);
    buf->pos += len;
  }
}

void print_array(FILE* f, const uint8_t* array, uint32_t len) {
  if(array) {
    for(int i=0; i<len; i++) {
      fprintf(f, "%02x", array[i]);
    }
    fprintf(f, "\n");
  }
  else {
    fprintf(f, "null\n");
  }
}

int sprng_random(void* context, uint8_t* buffer, size_t size) { // TODO improve!
  FILE* f = fopen("/dev/urandom", "rb");
  fread(buffer, 1, size, f);
  fclose(f);
  return 0;
}

static int generate_unique_keys(const char* model_id, int num_keys) {

  aes_key_t model_key;
  if(!get_model_key(model_id, &model_key)) {
    return 0;
  }

  setlocale(LC_NUMERIC, "en_US.UTF-8");
  fprintf(stderr, "Generating unique keys for model %s, please wait...\n", model_id);

  aes_key_t generator_key = GENERATOR_KEY;

  aes_key_t auth_data[4];
  memcpy(auth_data[0], generator_key, sizeof(aes_key_t));
  memcpy(auth_data[2], model_key, sizeof(aes_key_t));
  memcpy(auth_data[3], generator_key, sizeof(aes_key_t));

  sha_hash_t auth_hash;
  sha_hash_t hash_zero = {0};

  for(int i=0; i<num_keys; i++) {
    int j = 0;
    while(1) {

      if((j&0xff) == 0) {
        aes_key_t randomKey;
        sprng_random(NULL, randomKey, sizeof(aes_key_t));
        memcpy(auth_data[1], randomKey, sizeof(aes_key_t));
      }

      if((j&0xffff) == 0) {
        fprintf(stderr, "\rTried %'d unique id's...", j);
        fflush(stderr);
      }

      auth_data[1][0] = j&0xff;

      mbedtls_sha256_ret((uint8_t*)auth_data, sizeof(auth_data), auth_hash, 0);

      if(memcmp(hash_zero, auth_hash, GENERATOR_DIFFICULTY)==0) {
        fprintf(stderr, "Found unique key\n");
        print_array(stdout, auth_data[1], 16);
        print_array(stderr, auth_hash, sizeof(sha_hash_t));
        break;
      }

      j++;
    }
  }

  return 1;
}

static int create_fwpk_enc_package(const char* filename, const char* model_id) {

  aes_key_t model_key;
  if(!get_model_key(model_id, &model_key)) {
    return 0;
  }

  printf("Creating firmware package for model %s\n", model_id);

  // Import private signing key
  mbedtls_rsa_context private_key;
  mbedtls_rsa_init(&private_key, MBEDTLS_RSA_PKCS_V21, MBEDTLS_MD_SHA1);

  mbedtls_mpi_read_string(&private_key.N, 16, RSA_SIGN_KEY_MODULO);
  mbedtls_mpi_read_string(&private_key.D, 16, RSA_SIGN_KEY_PRIVATE_EXP);
  mbedtls_mpi_read_string(&private_key.E, 16, RSA_KEY_PUBLIC_EXP);
  private_key.len = RSA_KEY_BITSIZE/8;

  int err = mbedtls_rsa_complete(&private_key);
  assert(!err);

  // Load firmware file
  buffer_t* firmware_buf = buf_from_file(filename);
  if(!firmware_buf) {
    return 0;
  }

  // Create firmware hash
  sha_hash_t firmware_hash;
  err = mbedtls_sha1_ret(firmware_buf->data, firmware_buf->len, firmware_hash);
  assert(!err);

  // Sign the firmware hash TODO: rng
  rsa_sign_t firmware_sign;
  err = mbedtls_rsa_rsassa_pss_sign(&private_key, sprng_random, NULL, MBEDTLS_RSA_PRIVATE, MBEDTLS_MD_SHA1, 0, firmware_hash, firmware_sign);
  assert(!err);

  mbedtls_rsa_free(&private_key);

  // Create package binary (.fwpk)
  uint32_t fwpk_buf_size = 4*8 + strlen(model_id)+1 + firmware_buf->len + sizeof(rsa_sign_t);
  uint32_t fwpk_buf_size_aligned = ALIGN16(fwpk_buf_size);
  buffer_t* fwpk_buf = buf_alloc(fwpk_buf_size_aligned);
  write_chunk(fwpk_buf, "FWPK", NULL, 0);
  write_chunk(fwpk_buf, "MODL", model_id, strlen(model_id)+1);
  write_chunk(fwpk_buf, "FRMW", firmware_buf->data, firmware_buf->len);
  write_chunk(fwpk_buf, "SIGN", firmware_sign, sizeof(rsa_sign_t));
  assert(fwpk_buf->pos==fwpk_buf_size);
  free(firmware_buf);
  // buf_print("fwpk", fwpk_buf);

  // Encrypt package binary (.fwpk.enc)
  aes_iv_t aes_iv;
  sprng_random(NULL, (unsigned char*)&aes_iv, sizeof(aes_iv_t));
  
  buffer_t* fwpk_enc_buf = buf_alloc(16 + sizeof(aes_iv_t) + fwpk_buf->len);
  buf_write(fwpk_enc_buf, "ENCC", 4);
  buf_write_uint32(fwpk_enc_buf, fwpk_buf->pos);
  buf_write_uint32(fwpk_enc_buf, fwpk_buf->len);
  buf_seek(fwpk_enc_buf, 4);
  buf_write(fwpk_enc_buf, aes_iv, sizeof(aes_iv_t));
  
  mbedtls_aes_context aes;
  mbedtls_aes_init(&aes);
  err = mbedtls_aes_setkey_enc(&aes, model_key, AES_KEY_BITSIZE);
  assert(!err);
  err = mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_ENCRYPT, fwpk_buf_size_aligned, aes_iv, fwpk_buf->data, buf_ptr(fwpk_enc_buf));
  assert(!err);
  mbedtls_aes_free(&aes);  
  free(fwpk_buf);
  buf_print("fwpk.enc", fwpk_enc_buf);

  // Write package to file
  char* filename_out = malloc(strlen(model_id) + 16);
  strcpy(filename_out, model_id);
  strcat(filename_out, ".fwpk.enc");
  buf_to_file(filename_out, fwpk_enc_buf);

  free(fwpk_enc_buf);
  free(filename_out);

  return 1;
}

int main(int argc, char* argv[]) {
  int opt;

  int action = ACTION_NONE;
  char* model_id = NULL;
  char* filename = NULL;
  int num_keys = 0;
  int local_mode = 0;

  while((opt = getopt(argc, argv, ":m:g:f:rv:l")) != -1) {
    switch(opt)
    {
    case 'm':
      model_id = strdup(optarg);
      break;
    case 'g':
      action = ACTION_GENERATE_KEY;
      num_keys = atoi(optarg);
      break;
    case 'f':
      action = ACTION_CREATE_PACKAGE;
      filename = strdup(optarg);
      break;
    case 'r':
      action = ACTION_REQUEST_TOKEN;
      break;
    case 'v':
      action = ACTION_VERIFY_PACKAGE;
      filename = strdup(optarg);
      break;
    case 'l':
      local_mode = 1;
      break;
    case ':':
      printf("Missing argument for option %c\n", optopt);
      break;
    default:
      break;
    }
  }

  if(action == ACTION_GENERATE_KEY) {
    if(model_id) {
      generate_unique_keys(model_id, num_keys);
    }
    else {
      printf("No model specified\n");
      print_usage();
    }
  }
  else if(action == ACTION_CREATE_PACKAGE) {
    if(filename && model_id) {
      if(create_fwpk_enc_package(filename, model_id) && !local_mode) {
        printf("Upload at https://console.firebase.google.com/u/0/project/%s/storage/%s.appspot.com/files\n",
               FIREBASE_PROJECT, FIREBASE_PROJECT);
      }
    }
    else {
      printf("No model specified\n");
      print_usage();
    }
  }
  else if(action == ACTION_REQUEST_TOKEN) {
    char* request_key = fota_request_token();
    assert(request_key!=NULL);
    
    const char* url[3] = { "https://europe-west2-", FIREBASE_PROJECT, ".cloudfunctions.net" };
    if(local_mode) {
      url[0] = "http://localhost:5001/";
      url[2] = "/europe-west2";
    }
    
    printf("curl %s%s%s/firmware?model=%s&token=%s -v --output %s.fwpk.enc2\n",
           url[0], url[1], url[2],
           fota_model_id(), request_key, fota_model_id());
  }
  else if(action == ACTION_VERIFY_PACKAGE) {
    buffer_t* fwpk_enc2_buf = buf_from_file(filename);

    buffer_t* firmware = fota_verify_package(fwpk_enc2_buf);
    // buffer_t* firmware = 0;
    free(fwpk_enc2_buf);

    if(firmware) {
      printf("Firmware is verified, proceed to installing the update!\n");
      printf("Contents: %s (len: %d)\n", firmware->data, firmware->len);
    }
    else {
      printf("Firmware did not pass verification\n");
    }

    free(firmware);
  }
  else {
    print_usage();
  }

  if(filename) free(filename);
  if(model_id) free(model_id);
}
