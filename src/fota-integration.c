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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "fota.h"
#include "mbedtls/aes.h"

FILE* g_package_file = NULL;
FILE* g_install_file = NULL;

int fotai_read_storage_page(uint8_t* buf, int page) {
  assert(g_package_file);
  printf("Read storage page %d\n", page);
  fseek(g_package_file, page*FOTA_STORAGE_PAGE_SIZE, SEEK_SET);
  fread(buf, 1, FOTA_STORAGE_PAGE_SIZE, g_package_file);
  return FOTA_NO_ERROR;
}

int fotai_write_firmware_page(uint8_t* buf, int page, int len) {
  assert(g_install_file);
  printf("Write install page %d (len=%d)\n", page, len);
  fseek(g_install_file, page*FOTA_INSTALL_PAGE_SIZE, SEEK_SET);
  fwrite(buf, 1, len, g_install_file);
  return FOTA_NO_ERROR;
}

int fotai_get_unique_key(fota_aes_key_t unique_key) {
  fota_aes_key_t unique_key_on_flash = {0xf6,0xb9,0x29,0x0d,0x46,0x4d,0xdd,0x28,0x9b,0xf9,0x11,0x4e,0xfe,0xd1,0x6d,0x50};
  memcpy(unique_key, unique_key_on_flash, sizeof(fota_aes_key_t));
  return FOTA_NO_ERROR;
}

int fotai_get_public_key(fota_rsa_key_t public_key, int type) {
  if(type == FOTA_PUBLIC_KEY_TYPE_ENCRYPTION) {
    unsigned char private_encr_key_on_flash[] = {
      0xe7, 0x7a, 0xdc, 0x08, 0x50, 0xe7, 0x15, 0x26, 0xaa, 0x47, 0xdc, 0xa5,
      0xe2, 0x81, 0xe2, 0x4c, 0x68, 0xd0, 0xed, 0x81, 0xbf, 0x09, 0xc8, 0x4d,
      0xd1, 0x78, 0x8a, 0xbf, 0xfe, 0x7d, 0x93, 0x43, 0xba, 0x27, 0x3e, 0x91,
      0xde, 0x98, 0x39, 0xed, 0x6d, 0x55, 0xed, 0x9a, 0x34, 0x32, 0xfb, 0x69,
      0xc6, 0x23, 0x77, 0x3f, 0xa6, 0x04, 0x3f, 0xf3, 0x9d, 0x45, 0xab, 0x61,
      0xd4, 0xab, 0x12, 0x70, 0x44, 0x9b, 0x63, 0x09, 0x64, 0xf2, 0x15, 0x76,
      0xcb, 0x44, 0x8f, 0x8f, 0x6b, 0x0c, 0x60, 0x8b, 0xb2, 0xb6, 0x1f, 0xaf,
      0x8c, 0x61, 0x56, 0xad, 0xec, 0x5a, 0xf2, 0x1f, 0x53, 0x68, 0x21, 0xcf,
      0xa1, 0x83, 0xef, 0x15, 0xf5, 0x13, 0xfa, 0xaa, 0xfe, 0x01, 0xb9, 0x08,
      0x7d, 0x74, 0x07, 0x7e, 0x86, 0x1c, 0x55, 0x7e, 0x4f, 0xe0, 0xc2, 0xa4,
      0x52, 0x73, 0xf1, 0xfd, 0xc0, 0x26, 0x18, 0x17
    };
    memcpy(public_key, private_encr_key_on_flash, sizeof(fota_rsa_key_t));
  }
  else if(type== FOTA_PUBLIC_KEY_TYPE_SIGNING) {
    unsigned char private_sign_key_on_flash[] = {
      0xc7, 0xae, 0x34, 0x95, 0xbc, 0xfb, 0x87, 0xf3, 0xfd, 0x94, 0xf6, 0xd6,
      0x79, 0x13, 0x5b, 0xd7, 0xec, 0x6e, 0x23, 0xdc, 0xa3, 0xbf, 0x8a, 0x9d,
      0x5e, 0x30, 0xcf, 0xa3, 0x68, 0xd3, 0x3b, 0xaa, 0x06, 0xb1, 0x48, 0x66,
      0x63, 0x42, 0xa6, 0xf9, 0xfd, 0x2f, 0x6c, 0xc0, 0x62, 0x83, 0xa8, 0x1c,
      0x33, 0x95, 0x4c, 0x6c, 0x8e, 0x52, 0x62, 0xf0, 0xed, 0x39, 0xc7, 0xe4,
      0xa3, 0x5f, 0xe8, 0x23, 0x20, 0x9e, 0xbf, 0xf6, 0x51, 0x57, 0x63, 0x70,
      0x34, 0x3b, 0xd9, 0xe6, 0x5d, 0xb0, 0x6c, 0xae, 0xf2, 0xdb, 0x25, 0x2d,
      0xe7, 0x62, 0x06, 0xc7, 0x76, 0x61, 0xf2, 0xf3, 0xfb, 0x56, 0x83, 0xac,
      0x29, 0xd9, 0x12, 0x85, 0x3c, 0x50, 0x1d, 0x7b, 0x86, 0xdd, 0xa4, 0x20,
      0xcf, 0xb7, 0xad, 0x94, 0x7c, 0x59, 0x6f, 0x8f, 0x60, 0x2b, 0x5f, 0xe4,
      0x76, 0xd4, 0x1f, 0xe0, 0xda, 0xb7, 0xb1, 0x49
    };
    memcpy(public_key, private_sign_key_on_flash, sizeof(fota_rsa_key_t));
  }
  else {
    return FOTA_ERROR_BAD_ARGUMENTS;
  }
  return FOTA_NO_ERROR;
}

void fotai_get_aux_request_data(uint8_t* buf, int max_len) {
  char tmpbuf[1024];
  char data[] = "MyAuxData-";
  int datalen = strlen(data);

  int i=0, k=max_len;
  while(k>0) {
    memcpy(tmpbuf+i*datalen, data, datalen);
    k-=datalen;
    i++;
  }

  tmpbuf[max_len-1] = '\0';
  memcpy(buf, tmpbuf, max_len);
}

void fotai_generate_random(uint8_t* buf, int len) {
  FILE* f = fopen("/dev/urandom", "rb");
  fread(buf, 1, len, f);
  fclose(f);
}

int fotai_aes_decrypt_init(fota_aes_key_t key, void** ctx) {
  mbedtls_aes_context* aes_ctx = malloc(sizeof(mbedtls_aes_context));
  if(!aes_ctx) return FOTA_ERROR_AES_DECRYPT_FAILED;

  mbedtls_aes_init(aes_ctx);
  int err = mbedtls_aes_setkey_dec(aes_ctx, key, FOTA_AES_KEY_BITSIZE);
  if(err) return err;

  *ctx = aes_ctx;

  return FOTA_NO_ERROR;
}

int fotai_aes_decrypt_block(fota_aes_key_t key, uint8_t* in, uint8_t* out, int len, fota_aes_iv_t iv, void* ctx) {
  return mbedtls_aes_crypt_cbc((mbedtls_aes_context*)ctx,
                               MBEDTLS_AES_DECRYPT,
                               FOTA_STORAGE_PAGE_SIZE,
                               iv, in, out);
}

void fotai_aes_decrypt_free(void* ctx) {
  mbedtls_aes_free((mbedtls_aes_context*)ctx);
  free(ctx);
}
