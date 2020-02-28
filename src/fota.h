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
