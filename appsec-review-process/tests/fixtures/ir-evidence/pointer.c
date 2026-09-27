#include <stddef.h>

int sum_bytes(const unsigned char *buffer, size_t length) {
    int total = 0;
    for (size_t index = 0; index < length; ++index) {
        total += buffer[index];
    }
    return total;
}
