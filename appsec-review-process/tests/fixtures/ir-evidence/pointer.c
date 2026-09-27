#include <stddef.h>

int greet(const unsigned char *buffer, size_t length) {
    int total = 0;
    for (size_t index = 0; index < length; ++index) {
        total += buffer[index];
    }
    return total;
}

int main(void) {
    const unsigned char message[] = "hello";
    return greet(message, sizeof(message) - 1) == 532 ? 0 : 1;
}
