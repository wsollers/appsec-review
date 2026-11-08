#include <stdio.h>

#include "../../common/include/util.h"

int main(int argc, char **argv) {
    const char *text = argc > 1 ? argv[1] : "one two three";
    printf("%zu\n", util_count_words(text));
    return 0;
}
