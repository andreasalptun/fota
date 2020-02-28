#ifndef BUFFER_H
#define BUFFER_H

#include <stdint.h>
#include <memory.h>

#define buf_ptr(buf) ((buf)->data + (buf)->pos)
#define buf_available(buf) ((buf)->len - (buf)->pos)

// #define buf_write_uint32(buf, val) do { *((uint32_t*)((buf)->data + (buf)->pos)) = (uint32_t)val; (buf)->pos+=4; } while(0)
//TODO make function ^
// typedef unsigned char byte;

typedef struct {
  uint32_t len;
  uint32_t pos;
  uint8_t data[1];
} buffer_t;

buffer_t* buf_alloc(uint32_t size);
// void buf_align_size(buffer_t* buf, int align);

buffer_t* buf_from_file(const char* filename);
int buf_to_file(const char* filename, buffer_t* buf);

int buf_write(buffer_t* buf, const void* src, uint32_t count);

static int buf_write_uint32(buffer_t* buf, uint32_t val) {
  // TODO check overflow
  *((uint32_t*)(buf->data + buf->pos)) = val;
  buf->pos += 4;
  return 4;
}

static uint8_t* buf_seek(buffer_t* buf, int n) {
  // TODO check overflow
  uint8_t* p = buf_ptr(buf);
  buf->pos += 4;
  return p;
}

static int buf_read(buffer_t* buf, void* dst, uint32_t count) {
  if(buf->pos + count > buf->len)
    count = buf->len - buf->pos;
  memcpy(dst, buf->data + buf->pos, count);
  buf->pos += count;
  return count;
}

static uint32_t buf_read_uint32(buffer_t* buf) {
  // TODO check overflow
  uint32_t v = *((uint32_t*)(buf->data + buf->pos));
  buf->pos += 4;
  return v;
}


void buf_print(const char* name, buffer_t* buf);

#endif //BUFFER_H










