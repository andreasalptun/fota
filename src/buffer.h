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

#ifndef BUFFER_H
#define BUFFER_H

#include <stdint.h>

#define buf_ptr(buf) ((buf)->data + (buf)->pos)
#define buf_seekto(buf, newpos) ((buf)->pos = newpos)
#define buf_available(buf) ((buf)->len - (buf)->pos)

typedef struct {
  uint32_t len;
  uint32_t pos;
  uint8_t data[1];
} buffer_t;

buffer_t* buf_alloc(uint32_t size);
buffer_t* buf_copy(buffer_t* buf);

buffer_t* buf_from_file(const char* filename);
int buf_to_file(const char* filename, buffer_t* buf);

int buf_write(buffer_t* buf, const void* src, uint32_t n);
int buf_write_uint32(buffer_t* buf, uint32_t val);

int buf_read(buffer_t* buf, void* dst, uint32_t n);
uint32_t buf_read_uint32(buffer_t* buf);

uint8_t* buf_seek(buffer_t* buf, int n);

void buf_print(const char* name, buffer_t* buf);

#endif //BUFFER_H










