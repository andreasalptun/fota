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

#ifndef FOTA_CONFIG_H
#define FOTA_CONFIG_H

// TODO add FOTA_ prefix

#warning "Sample config! Copy fota-config-sample.h to fota-config.h and use project specific keys"

// System config
// Page size of the memory on which the downloaded firmware package is stored, usually an external flash chip
#define FOTA_STORAGE_PAGE_SIZE 256
// Page size of the memory where the firmware will be installed, usually internal flash
#define FOTA_INSTALL_PAGE_SIZE 512

// Crypto config
#define RSA_KEY_BITSIZE 1024
#define AES_KEY_BITSIZE 128

// Models
#define MODEL_ID_MK1 "mk1"
#define MODEL_KEY_MK1 {0x51,0x92,0x19,0x26,0x94,0x31,0x50,0x64,0x68,0xc1,0xf8,0x99,0x59,0x5a,0xfe,0x29}
#define MODEL_KEYS {{MODEL_ID_MK1, MODEL_KEY_MK1}}

// Generator key
#ifdef FOTA_TOOL
#define GENERATOR_KEY {0x33,0x71,0xae,0x3b,0xdf,0xc3,0x8d,0x0c,0x11,0xd4,0x9e,0x22,0x3a,0x26,0x55,0x47}
#define GENERATOR_DIFFICULTY 3
#endif

// Private key
#ifdef FOTA_TOOL
#define RSA_SIGN_KEY_PRIVATE_EXP "9f51ad7f33b3f57b857e8f9bfc2aa803160fa2e96e756b61b83f75cc49dd1023cf07305f111fa31e9f1671cce64d699a66c5de9e56c8014d7dd9b65604cc86e7e7388ea0623fe9911a38bdd448e86fe061dc67f5a8dbeda8f14af50c845fd254c03167379a8ccc9c43365e992dbe8af1e3ec34e8c8a502312395ffe2ce273a21"
#endif

// NOTE:
// Private encryption key pem and generator key+difficulty must also be added to firebase/functions/index.js

// Firebase project
#ifdef FOTA_TOOL
#define FIREBASE_PROJECT "xxx-fota"
#endif

#endif //FOTA_CONFIG_H
