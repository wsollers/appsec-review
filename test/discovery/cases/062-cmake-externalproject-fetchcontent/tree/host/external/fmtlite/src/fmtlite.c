#include "fmtlite.h"
int fmtlite_width(int value) { int width = 1; while (value >= 10) { value /= 10; width++; } return width; }
