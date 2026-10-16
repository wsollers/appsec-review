#include "util.h"
int helper_a(int v);
int parse_record(const char *rec, int n) {
  char out[16];
  int copied = copy_field(out, rec, n);
  return helper_a(copied) + out[0];
}
