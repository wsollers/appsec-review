/* SEI CERT FIO30-C focused fixture. */
#include <stdio.h>
#include <syslog.h>

void log_user(const char *user) {
  // cert: positive appsec-review.sei-cert.c.fio30-c.nonliteral-format-without-arguments
  printf(user);
}

void log_error(const char *message) {
  // cert: variant appsec-review.sei-cert.c.fio30-c.nonliteral-format-without-arguments
  fprintf(stderr, message);
}

void audit(const char *entry) {
  // cert: variant appsec-review.sei-cert.c.fio30-c.nonliteral-format-without-arguments
  syslog(LOG_INFO, entry);
}

void copy_message(char *out, size_t size, const char *message) {
  // cert: variant appsec-review.sei-cert.c.fio30-c.nonliteral-format-without-arguments
  snprintf(out, size, message);
}

void log_user_safely(const char *user) {
  // cert: safe-alternative appsec-review.sei-cert.c.fio30-c.nonliteral-format-without-arguments
  printf("%s", user);
}

void banner(void) {
  // cert: negative appsec-review.sei-cert.c.fio30-c.nonliteral-format-without-arguments
  printf("ready\n");
}

void with_arguments(const char *format, int value) {
  // cert: near-miss appsec-review.sei-cert.c.fio30-c.nonliteral-format-without-arguments
  printf(format, value);
}

void print_line(const char *text) {
  // cert: near-miss appsec-review.sei-cert.c.fio30-c.nonliteral-format-without-arguments
  puts(text);
}
