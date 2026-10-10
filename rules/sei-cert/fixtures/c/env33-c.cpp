// SEI CERT ENV33-C (applies to C++) focused fixture.
#include <cstdio>
#include <cstdlib>
#include <string>

namespace tools {
int run(const std::string& command) {
  // cert: positive appsec-review.sei-cert.cpp.env33-c.command-processor-call
  return std::system(command.c_str());
}

int run_unqualified(const char* command) {
  // cert: variant appsec-review.sei-cert.cpp.env33-c.command-processor-call
  return system(command);
}

int run_global(const char* command) {
  // cert: variant appsec-review.sei-cert.cpp.env33-c.command-processor-call
  return ::system(command);
}

bool processor_available() {
  // cert: exception:ENV33-C-EX1 appsec-review.sei-cert.cpp.env33-c.command-processor-call
  return std::system(nullptr) != 0;
}

bool shell_configured() {
  // cert: negative appsec-review.sei-cert.cpp.env33-c.command-processor-call
  return std::getenv("SHELL") != nullptr;
}

struct Runner {
  int system(const char* command) const { return command != nullptr; }
};

int member_call(const Runner& runner, const char* command) {
  // cert: near-miss appsec-review.sei-cert.cpp.env33-c.command-processor-call
  return runner.system(command);
}
}  // namespace tools
