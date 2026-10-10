// SEI CERT ERR34-C (applies to C++) focused fixture.
#include <cerrno>
#include <cstdlib>
#include <string>

namespace parse {
int count(const char* text) {
  // cert: positive appsec-review.sei-cert.cpp.err34-c.unchecked-conversion-function
  return std::atoi(text);
}

long total(const std::string& text) {
  // cert: variant appsec-review.sei-cert.cpp.err34-c.unchecked-conversion-function
  return atol(text.c_str());
}

long checked(const char* text, char** end) {
  errno = 0;
  // cert: safe-alternative appsec-review.sei-cert.cpp.err34-c.unchecked-conversion-function
  return std::strtol(text, end, 10);
}

struct Parser {
  int atoi(const char* text) const { return text != nullptr; }
};

int member(const Parser& parser, const char* text) {
  // cert: near-miss appsec-review.sei-cert.cpp.err34-c.unchecked-conversion-function
  return parser.atoi(text);
}
}  // namespace parse
