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

#include "buffer.h"

#include <stdio.h>
#include <stdlib.h>
#include <memory.h>

#define min(a,b) \
  ({ __typeof__ (a) _a = (a); \
     __typeof__ (b) _b = (b); \
     _a < _b ? _a : _b; })

buffer_t* buf_alloc(uint32_t size) {
  buffer_t* buf = malloc(sizeof(buffer_t) + size);
  memset(buf, 0, sizeof(buffer_t) + size);
  buf->len = size;
  return buf;
}

buffer_t* buf_from_file(const char* filename) {

  FILE* f = fopen(filename, "rb");
  if(!f) {
    fprintf(stderr, "File not found: %s\n", filename);
    return NULL;
  }

  fprintf(stderr, "Reading file %s ", filename);
  fseek(f, 0, SEEK_END);
  int32_t file_size = ftell(f);
  fseek(f, 0, SEEK_SET);

  buffer_t* buf = buf_alloc(file_size);

  int read;
  int n;
  while((n = fread(buf_ptr(buf), 1, 1024, f)) > 0) {
    buf->pos += n;
  }
  if(buf->pos != file_size) {
    fprintf(stderr, "Read error\n");
    free(buf);
    return NULL;
  }

  buf->len = file_size;
  buf->pos = 0;

  fprintf(stderr, "(%d bytes)\n", file_size);

  fclose(f);
  return buf;
}

int buf_to_file(const char* filename, buffer_t* buf) {
  FILE* f = fopen(filename, "wb");
  if(!f) {
    fprintf(stderr, "Unable to write to file: %s\n", filename);
    return 0;
  }

  fprintf(stderr, "Writing file %s ", filename);
  int remaining = buf->len;
  while(remaining > 0) {
    int n = fwrite(buf_ptr(buf), 1, min(1024, remaining), f);
    remaining -= n;
    if(n<0 || remaining<0) {
      fclose(f);
      return 0;
    }
  }

  fprintf(stderr, "(%d bytes)\n", buf->pos);

  fclose(f);
  return 1;
}

int buf_write(buffer_t* buf, const void* src, uint32_t n) {
  if(buf->pos + n > buf->len)
    n = buf->len - buf->pos;
  memcpy(buf->data + buf->pos, src, n);
  buf->pos += n;
  return n;
}

int buf_write_uint32(buffer_t* buf, uint32_t val) {
  if(buf_available(buf) < 4)
    return 0;
  *((uint32_t*)(buf->data + buf->pos)) = htole32(val);
  buf->pos += 4;
  return 4;
}

int buf_read(buffer_t* buf, void* dst, uint32_t n) {
  if(buf->pos + n > buf->len)
    n = buf->len - buf->pos;
  memcpy(dst, buf->data + buf->pos, n);
  buf->pos += n;
  return n;
}

uint32_t buf_read_uint32(buffer_t* buf) {
  if(buf_available(buf) < 4)
    return 0xdeadbeef;
  uint32_t v = *((uint32_t*)(buf->data + buf->pos));
  buf->pos += 4;
  return le32toh(v);
}

uint8_t* buf_seek(buffer_t* buf, int n) {
  if(buf->pos + n > buf->len)
    return NULL;
  uint8_t* p = buf_ptr(buf);
  buf->pos += 4;
  return p;
}

void buf_print(const char* name, buffer_t* buf) {
  if(name) {
    fprintf(stderr, "%s: ", name);
  }
  if(buf) {
    for(int i=0; i<buf->len; i++) {
      fprintf(stderr, "%02x", buf->data[i]);
    }
    fprintf(stderr, "\n");
  }
  else {
    fprintf(stderr, "null\n");
  }
}
