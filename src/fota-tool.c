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

#include <unistd.h>
#include <stdio.h>
#include <tomcrypt.h>

#define ACTION_NONE        0
#define ACTION_PACK        1
#define ACTION_REQUEST_KEY 2
#define ACTION_VERIFY     3

typedef struct {
  const char* model;
  aes_key_t key;
} model_key_t;

static void print_usage() {
  printf("Usage: fota-tool [-m model] [-f firmware] [-r request key] [-v verify] [-l local url]\n");
}

static void write_chunk(buffer_t* buf, const char* name, const void* data, uint32_t len) {
  assert(strlen(name)==4);
  assert(buf->pos + 8 + len <= buf->len);

  buf_write(buf, name, 4);
  buf_write_uint32(buf, htole32(len));

  if(data) {
    memcpy(buf_ptr(buf), data, len);
    buf->pos += len;
  }
}

static int pack_fwpk_enc(const char* filename, const char* model) {

  // Find model key
  int model_key_found = 0;
  aes_key_t model_key;
  model_key_t model_keys[] = MODEL_KEYS;
  for(int i=0; i<sizeof(model_keys)/sizeof(model_key_t); i++) {
    if(strcmp(model_keys[i].model, model)==0) {
      memcpy(model_key, model_keys[i].key, sizeof(aes_key_t));
      model_key_found = 1;
    }
  }
  if(!model_key_found) {
    printf("Model not found: %s\n", model);
    return 0;
  }
  
  printf("Creating firmware package for model %s\n", model);

  // Import private key
  rsa_key private_key;
  buffer_t* private_key_buf = buf_from_file(RSA_PRIVATE_KEY_FILE);
  assert(private_key_buf);
  int err = rsa_import(private_key_buf->data, private_key_buf->len, &private_key);
  assert(err==CRYPT_OK);
  free(private_key_buf);

  // Load firmware file
  buffer_t* firmware_buf = buf_from_file(filename);
  if(!firmware_buf) {
    return 0;
  }

  // Create firmware hash
  sha_hash_t firmware_hash;
  hash_state hash;
  sha256_init(&hash);
  err = sha256_process(&hash, firmware_buf->data, firmware_buf->len);
  assert(err==CRYPT_OK);
  err = sha256_done(&hash, firmware_hash);
  assert(err==CRYPT_OK);

  // Sign the firmware hash
  rsa_sign_t firmware_sign;
  unsigned long firmware_sign_len = sizeof(rsa_sign_t);
  err = rsa_sign_hash(firmware_hash,
                      sizeof(sha_hash_t),
                      firmware_sign,
                      &firmware_sign_len,
                      NULL,
                      find_prng("sprng"),
                      find_hash("sha256"),
                      8,
                      &private_key);
  assert(err==CRYPT_OK && firmware_sign_len == sizeof(rsa_sign_t));
  rsa_free(&private_key);

  // Create package binary (.fwpk)
  uint32_t fwpk_buf_size = 4*8 + strlen(model)+1 + firmware_buf->len + sizeof(rsa_sign_t);
  uint32_t fwpk_buf_size_aligned = ALIGN16(fwpk_buf_size);
  buffer_t* fwpk_buf = buf_alloc(fwpk_buf_size_aligned);
  write_chunk(fwpk_buf, "FWPK", NULL, 0);
  write_chunk(fwpk_buf, "MODL", model, strlen(model)+1);
  write_chunk(fwpk_buf, "FRMW", firmware_buf->data, firmware_buf->len);
  write_chunk(fwpk_buf, "SIGN", firmware_sign, sizeof(rsa_sign_t));
  assert(fwpk_buf->pos==fwpk_buf_size);
  free(firmware_buf);
  // buf_print("fwpk", fwpk_buf);

  // Encrypt package binary (.fwpk.enc)
  aes_iv_t iv;
  sprng_desc.read((unsigned char*)&iv, sizeof(aes_iv_t), NULL);

  buffer_t* fwpk_enc_buf = buf_alloc(16 + sizeof(aes_iv_t) + fwpk_buf->len);
  buf_write(fwpk_enc_buf, "ENCC", 4);
  buf_write_uint32(fwpk_enc_buf, fwpk_buf->pos);
  buf_write_uint32(fwpk_enc_buf, fwpk_buf->len);
  buf_seek(fwpk_enc_buf, 4);
  buf_write(fwpk_enc_buf, iv, sizeof(aes_iv_t));

  symmetric_CBC cbc;
  err = cbc_start(find_cipher("aes"), iv, model_key, sizeof(aes_key_t), 0, &cbc);
  assert(err==CRYPT_OK);
  err = cbc_encrypt(fwpk_buf->data, buf_ptr(fwpk_enc_buf), fwpk_buf_size_aligned, &cbc);
  assert(err==CRYPT_OK);
  free(fwpk_buf);
  buf_print("fwpk.enc", fwpk_enc_buf);

  // Write package to file
  char* filename_out = malloc(strlen(model) + 16);
  strcpy(filename_out, model);
  strcat(filename_out, ".fwpk.enc");
  buf_to_file(filename_out, fwpk_enc_buf);

  free(fwpk_enc_buf);
  free(filename_out);

  return 0;
}

int main(int argc, char* argv[]) {
  int opt;

  fota_init();

  int action = ACTION_NONE;
  char* model = NULL;
  char* filename = NULL;
  int local_url = 0;

  while((opt = getopt(argc, argv, ":m:f:rv:l")) != -1) {
    switch(opt)
    {
    case 'm':
      model = strdup(optarg);
      break;
    case 'f':
      action = ACTION_PACK;
      filename = strdup(optarg);
      break;
    case 'r':
      action = ACTION_REQUEST_KEY;
      break;
    case 'v':
      action = ACTION_VERIFY;
      filename = strdup(optarg);
      break;
    case 'l':
      local_url = 1;
      break;
    case ':':
    case '?':
      print_usage();
      break;
    }
  }

  if(action == ACTION_PACK) {
    if(filename && model) {
      if(pack_fwpk_enc(filename, model))
        printf("Upload at https://console.firebase.google.com/u/0/project/omotion-fota/storage/omotion-fota.appspot.com/files\n");
    }
    else {
      printf("No model specified\n");
      print_usage();
    }
  }
  else if(action == ACTION_REQUEST_KEY) {
    char* request_key = fota_request_key();
    printf("curl %s/firmware?model=%s&key=%s -v --output %s.fwpk.enc2\n",
           local_url ?
           "http://localhost:5001/omotion-fota/europe-west2" :
           "https://europe-west2-omotion-fota.cloudfunctions.net",
           fota_model_id(), request_key, fota_model_id());
  }
  else if(action == ACTION_VERIFY) {
    buffer_t* fwpk_enc2_buf = buf_from_file(filename);

    buffer_t* firmware = fota_verify(fwpk_enc2_buf);
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
  if(model) free(model);
}
