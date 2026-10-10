/* SEI CERT ERR34-C focused fixture. */
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>

int parse_count(const char *text) {
  // cert: positive appsec-review.sei-cert.c.err34-c.unchecked-conversion-function
  return atoi(text);
}

double parse_ratio(const char *text) {
  // cert: variant appsec-review.sei-cert.c.err34-c.unchecked-conversion-function
  return atof(text);
}

long long parse_total(const char *text) {
  // cert: variant appsec-review.sei-cert.c.err34-c.unchecked-conversion-function
  long long value = atoll(text);
  return value;
}

int scan_count(const char *text) {
  int value = 0;
  // cert: positive appsec-review.sei-cert.c.err34-c.scanf-numeric-conversion
  if (sscanf(text, "%d", &value) != 1) {
    return -1;
  }
  return value;
}

long read_offset(FILE *stream) {
  long value = 0;
  // cert: variant appsec-review.sei-cert.c.err34-c.scanf-numeric-conversion
  fscanf(stream, "offset=%ld", &value);
  return value;
}

int checked_count(const char *text, int *out) {
  char *end = NULL;
  errno = 0;
  // cert: safe-alternative appsec-review.sei-cert.c.err34-c.unchecked-conversion-function
  long value = strtol(text, &end, 10);
  if (end == text || *end != '\0' || errno == ERANGE || value > INT_MAX || value < INT_MIN) {
    return -1;
  }
  *out = (int)value;
  return 0;
}

int scan_name(const char *text, char name[16]) {
  // cert: near-miss appsec-review.sei-cert.c.err34-c.scanf-numeric-conversion
  return sscanf(text, "%15s", name);
}

int atoi_like(const char *text);
int caller(const char *text) {
  // cert: near-miss appsec-review.sei-cert.c.err34-c.unchecked-conversion-function
  return atoi_like(text);
}

int percent_literal(char *buffer, size_t size) {
  // cert: negative appsec-review.sei-cert.c.err34-c.scanf-numeric-conversion
  return snprintf(buffer, size, "%d%%", 5);
}
