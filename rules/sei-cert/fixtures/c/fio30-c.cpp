// SEI CERT FIO30-C (applies to C++) focused fixture.
#include <cstdio>
#include <string>

void show(const std::string& user) {
  // cert: positive appsec-review.sei-cert.cpp.fio30-c.nonliteral-format-without-arguments
  std::printf(user.c_str());
}

void show_unqualified(const char* user) {
  // cert: variant appsec-review.sei-cert.cpp.fio30-c.nonliteral-format-without-arguments
  fprintf(stderr, user);
}

void show_safely(const char* user) {
  // cert: safe-alternative appsec-review.sei-cert.cpp.fio30-c.nonliteral-format-without-arguments
  std::printf("%s", user);
}

void show_line(const char* text) {
  // cert: near-miss appsec-review.sei-cert.cpp.fio30-c.nonliteral-format-without-arguments
  std::puts(text);
}

void show_literal() {
  // cert: negative appsec-review.sei-cert.cpp.fio30-c.nonliteral-format-without-arguments
  std::printf("ready\n");
}
