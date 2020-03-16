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
#include "buffer.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <locale.h>
#include <assert.h>

#include "mbedtls/rsa.h"
#include "mbedtls/sha256.h"
#include "mbedtls/aes.h"

#define ACTION_NONE             0
#define ACTION_GENERATE_KEY     1
#define ACTION_CREATE_PACKAGE   2
#define ACTION_REQUEST_TOKEN    3
#define ACTION_VERIFY_PACKAGE   4
#define ACTION_INSTALL_FIRMWARE 5

#define ALIGN16(v) (((v)+15)&(~15))

typedef struct {
  const char* id;
  fota_aes_key_t key;
} model_key_t;

model_key_t model_keys[] = FOTA_MODEL_KEYS;

extern FILE* g_package_file;
extern FILE* g_install_file;

static void print_usage() {
  printf("Usage: fota-tool [-mgfrvil] <arg>\n");
  printf("  -m <model id>      model\n");
  printf("  -g <num keys>      generate unique keys\n");
  printf("  -f <firmware file> create firmware package (requires -m)\n");
  printf("                     add option -2 for installable package\n");
  printf("  -r                 generate request token (requires -m)\n");
  printf("  -v <package file>  verify package\n");
  printf("  -i <package file>  install package\n");
  printf("  -l                 local mode\n\n");
}

static int get_model_key(const char* model_id, fota_aes_key_t* model_key) {
  for(int i=0; i<sizeof(model_keys)/sizeof(model_key_t); i++) {
    if(strcmp(model_keys[i].id, model_id)==0) {
      memcpy(model_key, model_keys[i].key, sizeof(fota_aes_key_t));
      return 1;
    }
  }
  printf("model not found: %s\n", model_id);
  return 0;
}

static void print_array(FILE* f, const uint8_t* array, uint32_t len) {
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

static int nibble(int val) {
  unsigned int v = (val&0xf);
  return v>9 ? v-10+'a' : v+'0';
}

static int generate_unique_keys(const char* model_id, int num_keys) {

  fota_aes_key_t model_key;
  if(!get_model_key(model_id, &model_key)) {
    return 0;
  }

  setlocale(LC_NUMERIC, "en_US.UTF-8");
  fprintf(stderr, "Generating unique keys for model %s, please wait...\n", model_id);

  fota_aes_key_t generator_key = FOTA_GENERATOR_KEY;

  fota_aes_key_t auth_data[4];
  memcpy(auth_data[0], generator_key, sizeof(fota_aes_key_t));
  memcpy(auth_data[2], model_key, sizeof(fota_aes_key_t));
  memcpy(auth_data[3], generator_key, sizeof(fota_aes_key_t));

  uint8_t auth_hash[32];
  uint8_t hash_zero[32] = {0};

  for(int i=0; i<num_keys; i++) {
    int j = 0;
    while(1) {

      if((j&0xff) == 0) {
        fota_aes_key_t randomKey;
        fotai_generate_random(randomKey, sizeof(fota_aes_key_t));
        memcpy(auth_data[1], randomKey, sizeof(fota_aes_key_t));
      }

      if((j&0xffff) == 0) {
        fprintf(stderr, "\rTried %'d unique id's...", j);
        fflush(stderr);
      }

      auth_data[1][0] = j&0xff;

      mbedtls_sha256_ret((uint8_t*)auth_data, sizeof(auth_data), auth_hash, 0);

      if(memcmp(hash_zero, auth_hash, FOTA_GENERATOR_DIFFICULTY)==0) {
        fprintf(stderr, "Found unique key\n");
        print_array(stdout, auth_data[1], 16);
        print_array(stderr, auth_hash, sizeof(auth_hash));
        break;
      }

      j++;
    }
  }

  return 1;
}

static int generate_random(void* ctx, uint8_t* buf, size_t len) {
  fotai_generate_random(buf, len);
  return 0;
}

static buffer_t* encrypt_buffer(buffer_t* buf, fota_aes_key_t key) {
  fota_aes_iv_t iv;
  fotai_generate_random(iv, sizeof(fota_aes_iv_t));

  buffer_t* enc_buf = buf_alloc(FOTA_STORAGE_PAGE_SIZE + ALIGN16(buf->len));
  buf_write(enc_buf, "ENCC", 4);
  buf_write_uint32(enc_buf, buf->len);
  buf_seekto(enc_buf, 16);
  buf_write(enc_buf, iv, sizeof(fota_aes_iv_t));
  buf_seekto(enc_buf, FOTA_STORAGE_PAGE_SIZE);

  mbedtls_aes_context aes;
  mbedtls_aes_init(&aes);
  int err = mbedtls_aes_setkey_enc(&aes, key, FOTA_AES_KEY_BITSIZE);
  assert(!err);
  err = mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_ENCRYPT, buf->len, iv, buf->data, buf_ptr(enc_buf));
  assert(!err);
  mbedtls_aes_free(&aes);

  return enc_buf;
}

static buffer_t* create_fwpk_enc_package(const char* filename, const char* model_id) {
  assert(FOTA_STORAGE_PAGE_SIZE >= 16 + strlen(model_id)+1);

  fota_aes_key_t model_key;
  if(!get_model_key(model_id, &model_key)) {
    return NULL;
  }

  printf("Creating firmware package for model %s\n", model_id);

  // Load firmware file
  buffer_t* firmware_buf = buf_from_file(filename);
  if(!firmware_buf) {
    return NULL;
  }

  // Import private signing key
  mbedtls_rsa_context private_key;
  mbedtls_rsa_init(&private_key, MBEDTLS_RSA_PKCS_V21, MBEDTLS_MD_SHA256);

  fota_rsa_key_t modulo;
  fotai_get_public_key(modulo, FOTA_PUBLIC_KEY_TYPE_SIGNING);

  mbedtls_mpi_read_binary(&private_key.N, modulo, sizeof(fota_rsa_key_t));
  mbedtls_mpi_read_string(&private_key.D, 16, FOTA_RSA_SIGN_KEY_PRIVATE_EXPONENT);
  mbedtls_mpi_lset (&private_key.E, OPENSSL_RSA_PUBLIC_EXPONENT);
  private_key.len = FOTA_RSA_KEY_BITSIZE/8;

  int err = mbedtls_rsa_complete(&private_key);
  assert(!err);

  // Create firmware hash
  fota_sha_hash_t firmware_hash;
  err = mbedtls_sha256_ret(firmware_buf->data, firmware_buf->len, firmware_hash, 0);
  assert(!err);

  // Sign the firmware hash
  fota_rsa_key_t firmware_sign;
  err = mbedtls_rsa_rsassa_pss_sign(&private_key, generate_random, NULL, MBEDTLS_RSA_PRIVATE, MBEDTLS_MD_SHA256, 0, firmware_hash, firmware_sign);
  assert(!err);

  mbedtls_rsa_free(&private_key);

  // Create firmware package (.fwpk)
  buffer_t* fwpk_buf = buf_alloc(2*FOTA_STORAGE_PAGE_SIZE + ALIGN16(firmware_buf->len));
  buf_write(fwpk_buf, "FWPK", 4);
  buf_write_uint32(fwpk_buf, firmware_buf->len);
  buf_seekto(fwpk_buf, 16);
  buf_write(fwpk_buf, model_id, strlen(model_id)+1);
  buf_seekto(fwpk_buf, FOTA_STORAGE_PAGE_SIZE);
  buf_write(fwpk_buf, firmware_sign, sizeof(fota_rsa_key_t));
  buf_seekto(fwpk_buf, 2*FOTA_STORAGE_PAGE_SIZE);
  buf_write(fwpk_buf, firmware_buf->data, firmware_buf->len);

  free(firmware_buf);
  // buf_print("fwpk", fwpk_buf);

  // Encrypt package binary (.fwpk.enc)
  buffer_t* fwpk_enc_buf = encrypt_buffer(fwpk_buf, model_key);
  free(fwpk_buf);

  return fwpk_enc_buf;
}

int main(int argc, char* argv[]) {
  int opt;

  int action = ACTION_NONE;
  char* model_id = NULL;
  char* filename = NULL;
  int num_keys = 0;
  int local_mode = 0;
  int create_enc2 = 0;

  while((opt = getopt(argc, argv, ":m:g:f:2rv:i:l")) != -1) {
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
    case '2':
      create_enc2 = 1;
      break;
    case 'r':
      action = ACTION_REQUEST_TOKEN;
      break;
    case 'v':
      action = ACTION_VERIFY_PACKAGE;
      filename = strdup(optarg);
      break;
    case 'i':
      action = ACTION_INSTALL_FIRMWARE;
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
      buffer_t* fwpk_enc_buf = create_fwpk_enc_package(filename, model_id);

      if(fwpk_enc_buf) {
        // Uncomment the following line to print the fwpk.enc data in hex format
        // buf_print("fwpk.enc", fwpk_enc_buf);

        char* filename_out = malloc(strlen(model_id) + 16);
        strcpy(filename_out, model_id);

        if(create_enc2) {
          strcat(filename_out, ".fwpk.enc2");

          fota_aes_key_t unique_key;
          fotai_get_unique_key(unique_key);

          buffer_t* fwpk_enc2_buf = encrypt_buffer(fwpk_enc_buf, unique_key);

          buf_to_file(filename_out, fwpk_enc2_buf);

          free(fwpk_enc2_buf);
        }
        else {
          strcat(filename_out, ".fwpk.enc");
          buf_to_file(filename_out, fwpk_enc_buf);

          if(!local_mode) {
            printf("Upload at https://console.firebase.google.com/u/0/project/%s/storage/%s.appspot.com/files\n",
                   FOTA_FIREBASE_PROJECT, FOTA_FIREBASE_PROJECT);
          }
        }

        free(fwpk_enc_buf);
      }
    }
    else {
      printf("No model specified\n");
      print_usage();
    }
  }
  else if(action == ACTION_REQUEST_TOKEN) {
    fota_token_t token;
    int res = fota_request_token(token);
    assert(res!=0);

    char token_hex[2*sizeof(fota_token_t)+1];
    char* p = token_hex;
    for(int i=0; i<sizeof(fota_token_t); i++) {
      int b = token[i];
      *p++ = nibble(b>>4);
      *p++ = nibble(b);
    }
    *p = '\0';

    const char* url[3] = { "https://europe-west2-", FOTA_FIREBASE_PROJECT, ".cloudfunctions.net" };
    if(local_mode) {
      url[0] = "http://localhost:5001/";
      url[2] = "/europe-west2";
    }

    printf("curl %s%s%s/firmware?model=%s&token=%s -v --output %s.fwpk.enc2\n",
           url[0], url[1], url[2],
           fota_model_id(), token_hex, fota_model_id());
  }
  else if(action == ACTION_VERIFY_PACKAGE) {

    g_package_file = fopen(filename, "rb");

    if(fota_verify_package()) {
      printf("Firmware is verified, proceed to installing the update!\n");
    }
    else {
      printf("Firmware did not pass verification!\n");
    }

    fclose(g_package_file);
    g_package_file = NULL;
  }
  else if(action == ACTION_INSTALL_FIRMWARE) {

    char* filename_install = malloc(strlen(filename) + 16);
    strcpy(filename_install, filename);
    strcat(filename_install, ".inst");

    g_package_file = fopen(filename, "rb");
    g_install_file = fopen(filename_install, "wb");

    if(fota_install_package()) {
      printf("Firmware is installed to file %s!\n", filename_install);
    }
    else {
      printf("Firmware installation failed!\n");
    }

    fclose(g_package_file);
    fclose(g_install_file);

    g_package_file = NULL;
    g_install_file = NULL;

    free(filename_install);
  }
  else {
    print_usage();
  }

  if(filename) free(filename);
  if(model_id) free(model_id);
}
