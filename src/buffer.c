#include "buffer.h"

#include <stdio.h>
#include <stdlib.h>
#include <memory.h>
#include <assert.h>

#define min(a,b) \
  ({ __typeof__ (a) _a = (a); \
     __typeof__ (b) _b = (b); \
     _a < _b ? _a : _b; })

buffer_t* buf_alloc(uint32_t size) {
  uint32_t padded_size = size;// + 16;//(size+15)&(~0xf); // Allow padding to 16 byte
  buffer_t* buf = malloc(sizeof(buffer_t) + padded_size);
  memset(buf, 0, sizeof(buffer_t) + padded_size);
  buf->len = size;
  return buf;
}

// void buf_align_size(buffer_t* buf, int align) {
//   assert(align<=16 && (align&(align-1))==0);
//   buf->len = (buf->len+(align-1))&(~0xf);
// }

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
  buf->pos = 0;
  while(remaining > 0) {
    int n = fwrite(buf_ptr(buf), 1, min(1024, remaining), f);
    remaining -= n;
    if(n<0 || remaining<0) {
      fclose(f);
      return 0;
    }
    buf->pos += n;
  }
  
  fprintf(stderr, "(%d bytes)\n", buf->pos);
  
  fclose(f);
  return 1;
}

int buf_write(buffer_t* buf, const void* src, uint32_t count) {
  if(buf->pos + count > buf->len)
    count = buf->len - buf->pos;
  memcpy(buf->data + buf->pos, src, count);
  buf->pos += count;
  return count;
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
