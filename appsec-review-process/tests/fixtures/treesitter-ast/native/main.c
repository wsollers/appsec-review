#include <string.h>
#include "local.h"

static void copy(char *dst, const char *src) {
    strcpy(dst, src);
}

int main(void) {
    char buf[8];
    copy(buf, "hi");
    return 0;
}
