#include <stdio.h>

int main(void) {
    int *pointer = NULL; // CWE-476 toy
    if (pointer) { printf("%d\n", *pointer); }
    return 0;
}
