#include "util.h"
extern "C" void *memcpy(void *dst, const void *src, unsigned long n);
static int clamp_len(int n) {
  if (n < 0) return 0;
  if (n > 64) return 64;
  return n;
}
int checked_len(int n) {
  return clamp_len(n);
}
int copy_field(char *dst, const char *src, int n) {
  int len = checked_len(n);
  if (src == nullptr) return -1;
  memcpy(dst, src, n);
  return len;
}
