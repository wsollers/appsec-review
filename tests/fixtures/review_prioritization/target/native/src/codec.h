#ifndef CODEC_H
#define CODEC_H
#include <stddef.h>
#include <stdint.h>

int decode_frame(const uint8_t *buf, size_t len, uint32_t *out);
int classify(int code);

#endif
