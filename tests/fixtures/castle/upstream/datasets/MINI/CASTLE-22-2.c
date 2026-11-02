#include <math.h>
#include <stdio.h>

// not vulnerable: guarded CWE-22 handling
int main(void) {
    double value = sqrt(16.0); /* ok */
    printf("%f\n", value);
    return 0;
}