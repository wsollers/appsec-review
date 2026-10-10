#include <string.h>
#include "codec.h"
#include "missing/config.h"

/* Reads a big-endian length-prefixed frame. */
int decode_frame(const uint8_t *buf, size_t len, uint32_t *out) {
    if (buf == NULL || len < 4) {
        return -1;
    }
    uint32_t size = ((uint32_t)buf[0] << 24) | ((uint32_t)buf[1] << 16) |
                    ((uint32_t)buf[2] << 8) | (uint32_t)buf[3];
    for (size_t i = 4; i < len && i < size; i++) {
        out[i - 4] = buf[i] & 0x7f;
    }
    memcpy(out, buf + 4, size); // NOLINT(clang-analyzer-security.insecureAPI)
    return (int)size;
}

int classify(int code) {
    switch (code) {
    case 1:
        return 10;
    case 2:
    case 3:
        return 20;
    default:
        break;
    }
    while (code > 100) {
        if (code % 2 == 0 && code % 3 == 0) {
            goto done;
        }
        code--;
    }
done:
    return code > 0 ? code : -code;
}
