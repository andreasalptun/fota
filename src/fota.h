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

#ifndef FOTA_H
#define FOTA_H

#include "fota-config.h"
#include "buffer.h"

#define ALIGN16(v) (((v)+15)&(~15))

typedef unsigned char uuid_t[16];
typedef unsigned char rsa_sign_t[RSA_KEY_BITSIZE/8];
typedef unsigned char rsa_cipher_t[RSA_KEY_BITSIZE/8];
typedef unsigned char sha_hash_t[32];
typedef unsigned char aes_key_t[AES_KEY_BITSIZE/8];
typedef unsigned char aes_iv_t[16];

// Must be called before any of the function below
void fota_init();

// Returns a static model id string, do not free
const char* fota_model_id();

// Generates a request token hex string for downloading the firmware package from the server
// returned buffer should be free'd
char* fota_request_token();

// Verify package, unwrap it and return the firmware binary
// returned buffer should be free'd
buffer_t* fota_verify_package(buffer_t* fwpk_enc2_buf);

#endif //FOTA_H
