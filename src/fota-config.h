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

#define RSA_KEY_BITSIZE 1024
#define RSA_KEY_MODULO "e77adc0850e71526aa47dca5e281e24c68d0ed81bf09c84dd1788abffe7d9343ba273e91de9839ed6d55ed9a3432fb69c623773fa6043ff39d45ab61d4ab1270449b630964f21576cb448f8f6b0c608bb2b61faf8c6156adec5af21f536821cfa183ef15f513faaafe01b9087d74077e861c557e4fe0c2a45273f1fdc0261817"
#define RSA_KEY_PUBLIC_EXP "010001"

//---

#define AES_KEY_BITSIZE 128
#define MODEL_ID_MK1 "mk1"
#define MODEL_KEY_MK1 {0x51,0x92,0x19,0x26,0x94,0x31,0x50,0x64,0x68,0xc1,0xf8,0x99,0x59,0x5a,0xfe,0x29}
#define MODEL_KEYS {{MODEL_ID_MK1, MODEL_KEY_MK1}}
#define FIREBASE_PROJECT "xxx-fota"

#endif //FOTA_CONFIG_H
