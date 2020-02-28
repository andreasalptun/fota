#ifndef FOTA_CONFIG_H
#define FOTA_CONFIG_H

#define RSA_KEY_BITSIZE 1024
#define AES_KEY_BITSIZE 128
#define RSA_PRIVATE_KEY_FILE "keys/private.der"
#define RSA_PUBLIC_KEY_FILE "keys/public.der"
#define MODEL_ID_MK1 "mk1"
#define MODEL_KEY_MK1 {0x51,0x92,0x19,0x26,0x94,0x31,0x50,0x64,0x68,0xc1,0xf8,0x99,0x59,0x5a,0xfe,0x29}
#define MODEL_KEYS {{MODEL_ID_MK1, MODEL_KEY_MK1}}

#endif //FOTA_CONFIG_H
