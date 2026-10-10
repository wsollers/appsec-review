/* SEI CERT STR31-C focused fixture (unbounded input subset). */
#include <stdio.h>

void read_line(void) {
  char line[64];
  // cert: positive appsec-review.sei-cert.c.str31-c.gets-call
  gets(line);
  puts(line);
}

int read_line_checked(void) {
  char line[64];
  // cert: variant appsec-review.sei-cert.c.str31-c.gets-call
  if (gets(line) == NULL) {
    return -1;
  }
  return line[0];
}

int read_word(void) {
  char word[32];
  // cert: positive appsec-review.sei-cert.c.str31-c.unbounded-scanf-string
  return scanf("%s", word);
}

int read_pair(const char *input, char key[16], int *value) {
  // cert: variant appsec-review.sei-cert.c.str31-c.unbounded-scanf-string
  // cert: variant appsec-review.sei-cert.c.err34-c.scanf-numeric-conversion
  return sscanf(input, "%[^=]=%d", key, value);
}

int read_bounded(char word[32]) {
  // cert: safe-alternative appsec-review.sei-cert.c.str31-c.unbounded-scanf-string
  return scanf("%31s", word);
}

char *read_line_bounded(char *line, int size) {
  // cert: safe-alternative appsec-review.sei-cert.c.str31-c.gets-call
  return fgets(line, size, stdin);
}

int read_number(int *value) {
  // cert: near-miss appsec-review.sei-cert.c.str31-c.unbounded-scanf-string
  // cert: variant appsec-review.sei-cert.c.err34-c.scanf-numeric-conversion
  return scanf("%d", value);
}

char *gets_s_wrapper(char *line);
void wrapper(char *line) {
  // cert: near-miss appsec-review.sei-cert.c.str31-c.gets-call
  gets_s_wrapper(line);
}
