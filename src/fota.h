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

void        fota_init();
const char* fota_model_id();
char*       fota_request_key();
buffer_t*   fota_verify(buffer_t* fwpk_enc2_buf);

#endif //FOTA_H
