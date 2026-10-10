// SEI CERT EXP58-CPP focused fixture.
#include <cstdarg>
#include <string>

extern "C" {
void by_reference(const std::string& format, ...) {
  va_list args;
  // cert: positive appsec-review.sei-cert.cpp.exp58-cpp.va-start-invalid-parameter
  va_start(args, format);
  va_end(args);
}

void by_float(float scale, ...) {
  va_list args;
  // cert: variant appsec-review.sei-cert.cpp.exp58-cpp.va-start-invalid-parameter
  va_start(args, scale);
  va_end(args);
}

void by_char(int level, char marker, ...) {
  va_list args;
  // cert: variant appsec-review.sei-cert.cpp.exp58-cpp.va-start-invalid-parameter
  va_start(args, marker);
  va_end(args);
}

void by_int(int count, ...) {
  va_list args;
  // cert: safe-alternative appsec-review.sei-cert.cpp.exp58-cpp.va-start-invalid-parameter
  va_start(args, count);
  va_end(args);
}

void by_pointer(const char* format, ...) {
  va_list args;
  // cert: near-miss appsec-review.sei-cert.cpp.exp58-cpp.va-start-invalid-parameter
  va_start(args, format);
  va_end(args);
}

void reference_not_last(const std::string& name, int count, ...) {
  va_list args;
  // cert: negative appsec-review.sei-cert.cpp.exp58-cpp.va-start-invalid-parameter
  va_start(args, count);
  va_end(args);
}
}
