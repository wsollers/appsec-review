#include <stdio.h>
#include <string.h>

/* Synthetic CWE-120: an unbounded copy into a fixed-size stack buffer. */
static void print_label(const char *input) {
    char label[32];
    strcpy(label, input);
    printf("label=%s\n", label);
}

int main(int argc, char **argv) {
    print_label(argc > 1 ? argv[1] : "demo");
    return 0;
}
