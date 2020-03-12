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

#if (FOTA_STORAGE_PAGE_SIZE&(FOTA_STORAGE_PAGE_SIZE-1))!=0
#error FOTA_STORAGE_PAGE_SIZE must be power of two
#endif

#if (FOTA_INSTALL_PAGE_SIZE&(FOTA_INSTALL_PAGE_SIZE-1))!=0
#error FOTA_INSTALL_PAGE_SIZE must be power of two
#endif

#if (RSA_KEY_BITSIZE&(RSA_KEY_BITSIZE-1))!=0
#error RSA_KEY_BITSIZE must be power of two
#endif

#if (AES_KEY_BITSIZE&(AES_KEY_BITSIZE-1))!=0
#error AES_KEY_BITSIZE must be power of two
#endif

#if RSA_KEY_BITSIZE/8-42 < 2*AES_KEY_BITSIZE/8
#error RSA key too small or AES key too big (two AES keys must fit in RSA-OAEP encryption)
#endif

#if FOTA_STORAGE_PAGE_SIZE < 32
#error FOTA_STORAGE_PAGE_SIZE must be at least 32 bytes (must fit the ENCC header)
#endif

#if FOTA_INSTALL_PAGE_SIZE < FOTA_STORAGE_PAGE_SIZE
#error FOTA_INSTALL_PAGE_SIZE must be larger or equal to FOTA_STORAGE_PAGE_SIZE
#endif

#if FOTA_STORAGE_PAGE_SIZE < RSA_KEY_BITSIZE/8
#error FOTA_STORAGE_PAGE_SIZE must fit the RSA signature
#endif