#include "a.h"
#define TWICE(x) ((x) * 2)
template <typename T> T scale(T value) { return TWICE(value); }
int use() { return scale<int>(helper(3)); }
