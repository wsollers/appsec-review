#include <stddef.h>

#ifndef INDEX_BOUND
#define INDEX_BOUND 4
#endif

unsigned char nondet_uchar(void);

int main(void)
{
    unsigned char index = nondet_uchar();
    unsigned char buffer[4] = {0, 1, 2, 3};
    __CPROVER_assume(index < INDEX_BOUND);
    __CPROVER_assert(index < sizeof buffer, "cbmc fixture index bound");
    return buffer[index];
}
