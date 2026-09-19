#include <stdio.h>

static int helper(int value) {
    return value + 1;
}

int main(void) {
    printf("hello binary %d\n", helper(41));
    return 0;
}
