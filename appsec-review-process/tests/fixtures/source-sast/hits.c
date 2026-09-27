#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void copy_and_report(char *destination, const char *source, const char *format) {
    strcpy(destination, source);
    printf(format, source);
    memcpy(destination, source, strlen(source));
    system(source);
}
