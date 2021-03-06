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

int fotai_read_storage_page(uint8_t* buf, int page) { return FOTA_NO_ERROR; }
int fotai_write_firmware_page(uint8_t* buf, int page, int len) { return FOTA_NO_ERROR; }

int fotai_get_unique_key(fota_aes_key_t unique_key) { return FOTA_NO_ERROR; }
int fotai_get_public_key(fota_rsa_key_t public_key, int type) { return FOTA_NO_ERROR; }

void fotai_get_aux_request_data(uint8_t* buf, int max_len) {}

void fotai_generate_random(uint8_t* buf, int len) {}

int fotai_aes_decrypt_init(fota_aes_key_t key, void** ctx) { return FOTA_NO_ERROR; }
int fotai_aes_decrypt_block(fota_aes_key_t key, uint8_t* in, uint8_t* out, int len, fota_aes_iv_t iv, void* ctx) { return FOTA_NO_ERROR; }
void fotai_aes_decrypt_free(void* ctx) {}

int main() {
  
  fota_token_t token;
  if(!fota_request_token(token))
    return 1;
  fota_sha_hash_t firmware_hash;
  if(!fota_verify_package(firmware_hash)) {
    return 1;
  }

  if(!fota_install_package()) {
    return 1;
  }

  return 0;
}
