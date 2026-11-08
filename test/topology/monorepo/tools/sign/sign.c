#include <stdio.h>

static unsigned int stamp(const char *text) {
    unsigned int value = 0;
    while (*text != '\0') {
        value = value * 31u + (unsigned char)*text;
        ++text;
    }
    return value;
}

int main(int argc, char **argv) {
    printf("%u\n", stamp(argc > 1 ? argv[1] : ""));
    return 0;
}
