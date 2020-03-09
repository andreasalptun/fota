#include "fota.h"
#include <stddef.h>

int sprng_random(void* context, uint8_t* buffer, size_t size) {
  return 0;
}

int main() {
  if(!fota_request_token())
    return 1;

  buffer_t* buf = buf_alloc(1024);
  if(!fota_verify_package(buf)) {
    return 1;
  }

  return 0;
}
