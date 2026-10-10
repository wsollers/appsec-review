/* SEI CERT POS34-C focused fixture. */
#include <stdio.h>
#include <stdlib.h>

int set_home(const char *home) {
  char entry[256];
  snprintf(entry, sizeof entry, "HOME=%s", home);
  // cert: positive appsec-review.sei-cert.c.pos34-c.putenv-automatic-array
  return putenv(entry);
}

int set_mode(int verbose) {
  char setting[32] = "MODE=quiet";
  if (verbose) {
    // cert: variant appsec-review.sei-cert.c.pos34-c.putenv-automatic-array
    return putenv(setting);
  }
  return 0;
}

int set_static(void) {
  static char entry[32] = "MODE=static";
  // cert: near-miss appsec-review.sei-cert.c.pos34-c.putenv-automatic-array
  return putenv(entry);
}

int set_heap(const char *value) {
  char *entry = malloc(64);
  if (entry == NULL) {
    return -1;
  }
  snprintf(entry, 64, "MODE=%s", value);
  // cert: negative appsec-review.sei-cert.c.pos34-c.putenv-automatic-array
  return putenv(entry);
}

int set_safely(const char *home) {
  // cert: safe-alternative appsec-review.sei-cert.c.pos34-c.putenv-automatic-array
  return setenv("HOME", home, 1);
}

int set_through_alias(void) {
  char entry[32] = "MODE=alias";
  char *alias = entry;
  // cert: known-false-negative appsec-review.sei-cert.c.pos34-c.putenv-automatic-array
  return putenv(alias);
}
