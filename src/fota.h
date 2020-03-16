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

#if __has_include("fota-config.h")
#include "fota-config.h"
#else
#include "fota-config-sample.h"
#endif

#define FOTA_SHA_HASH_BITSIZE 256

#include "fota-sanity.h"
#include <stdint.h>

#define FOTA_PUBLIC_KEY_TYPE_SIGNING    0
#define FOTA_PUBLIC_KEY_TYPE_ENCRYPTION 1

#define OPENSSL_RSA_PUBLIC_EXPONENT 0x010001

typedef uint8_t fota_token_t[FOTA_RSA_KEY_BITSIZE/8];
typedef uint8_t fota_rsa_key_t[FOTA_RSA_KEY_BITSIZE/8];
typedef uint8_t fota_aes_key_t[FOTA_AES_KEY_BITSIZE/8];
typedef uint8_t fota_aes_iv_t[16];
typedef uint8_t fota_sha_hash_t[FOTA_SHA_HASH_BITSIZE/8];


// FOTA API
//

// Returns a static model id string, do not free
const char* fota_model_id(void);

// Generates a request token for downloading the firmware package from server.
// The generated token in placed in the fota_token_t buffer.
// Returns 1 if the request token was successfully generated.
int fota_request_token(fota_token_t token);

// Decrypt and verify package signature.
// Uses fotai_read_storage_page to read pages from the memory where the downloaded
// firmware package is stored. Uses fotai_aes_* for AES decryption.
// No data is modified during this process.
// Returns 1 if the firmware signature is valid.
int fota_verify_package(void);

// Decrypt and install the package.
// Uses fotai_read_storage_page to read pages from the memory where the downloaded
// firmware package is stored. Uses fotai_aes_* for AES decryption.
// Uses fotai_write_firmware_page to write pages to destination firmware flash memory.
// This function does not check the signature. Call fota_verify_package and
// check the result before installing.
// Returns 1 if the firmware was installed successfully.
int fota_install_package(void);


// FOTA integration functions, must be supplied by the system. Example integration in fota-integration.c
//

// Read a single memory page from where the downloaded firmware package is stored,
// usually an external flash chip. The size of a page is defined by FOTA_STORAGE_PAGE_SIZE
// and the provided buffer will be large enough to fit a page. Page 0 is expected to be
// the first page of the firmware package, starting at byte 0.
extern void fotai_read_storage_page(uint8_t* buf, int page);

// Write a single memory page to where the firmware is stored, usually the internal
// flash memory. The size of a page is defined by FOTA_INSTALL_PAGE_SIZE. Page 0 is
// the first page of the decrypted firmware, starting at byte 0. The len parameter
// is FOTA_INSTALL_PAGE_SIZE except for the last written page, where it might be less.
extern void fotai_write_firmware_page(uint8_t* buf, int page, int len); // TODO perhaps these functions should return something?

// Read the unique key from flash memory into the provided buffer.
extern void fotai_get_unique_key(fota_aes_key_t unique_key);

// Read a public key (rsa key modulo) from flash memory into the provided buffer.
// The type parameter is either FOTA_PUBLIC_KEY_TYPE_SIGNING or FOTA_PUBLIC_KEY_TYPE_ENCRYPTION.
extern void fotai_get_public_key(fota_rsa_key_t public_key, int type);

// Append auxillary data to the token, which will be encrypted together with the keys
// using RSA-OAEP. This can be any data needed on the server, for example a serial number
// or other device info. The length depends on the size of the RSA key.
extern void fotai_get_aux_request_data(uint8_t* buf, int len);

// Generate len random bytes into the provided buffer. On system the random bytes are
// used for RSA-OAEP padding generation and should preferably be cryptographically secure.
extern void fotai_generate_random(uint8_t* buf, int len);

// Initialize AES-128-CBC decryption with the provided decryption key. If the decryption
// requires a context it can be set by dereferencing ctx and setting it as a void pointer.
extern void fotai_aes_decrypt_init(fota_aes_key_t key, void** ctx);

// Decrypt a block of size len bytes from in to out, using the provided initialization
// vector. The initialization vector will be modified in each call, allowing this function
// to be called multiple times for consecutive blocks. The block len is a multiple of
// of 16 bytes. If a context is provided in the init function, it will be accessible
// from the ctx pointer.
extern void fotai_aes_decrypt_block(uint8_t* in, uint8_t* out, int len, fota_aes_iv_t iv, void* ctx);

// Releases memory allocated by the init function, if necessary. If a context is provided
// in the init function, it will be accessible from the ctx pointer.
extern void fotai_aes_decrypt_free(void* ctx);

#endif //FOTA_H
