#include "hash.h"
#include <stdio.h>
int main(void) { printf("%u\n", hash_bytes((const unsigned char *)"abc", 3)); return 0; }
