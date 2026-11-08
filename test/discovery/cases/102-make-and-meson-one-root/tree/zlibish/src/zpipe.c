#include "zlibish.h"
int main(void) { char out; return zl_deflate("a", &out) == 1 ? 0 : 1; }
