#include <stdio.h>

#include "tinylib.h"

int main(void) {
    printf("server %d\n", tinylib_add(2, 3));
    return 0;
}
