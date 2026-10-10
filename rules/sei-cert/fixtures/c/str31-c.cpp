// SEI CERT STR31-C (applies to C++) focused fixture.
#include <cstdio>
#include <iostream>
#include <string>

void legacy_read() {
  char line[64];
  // cert: positive appsec-review.sei-cert.cpp.str31-c.gets-call
  std::gets(line);
}

void unqualified_read() {
  char line[64];
  // cert: variant appsec-review.sei-cert.cpp.str31-c.gets-call
  gets(line);
}

void modern_read(std::string& line) {
  // cert: safe-alternative appsec-review.sei-cert.cpp.str31-c.gets-call
  std::getline(std::cin, line);
}

struct Reader {
  void gets(char* line) const { line[0] = '\0'; }
};

void member(const Reader& reader, char* line) {
  // cert: near-miss appsec-review.sei-cert.cpp.str31-c.gets-call
  reader.gets(line);
}
