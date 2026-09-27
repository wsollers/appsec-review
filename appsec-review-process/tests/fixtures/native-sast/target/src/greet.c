#include <stdio.h>
#include <string.h>

void greet(char *dst, const char *src) {
    strcpy(dst, src);
    printf(src);
}
