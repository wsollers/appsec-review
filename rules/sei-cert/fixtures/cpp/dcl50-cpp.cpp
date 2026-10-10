// SEI CERT DCL50-CPP focused fixture.
#include <cstdarg>
#include <type_traits>

// cert: positive appsec-review.sei-cert.cpp.dcl50-cpp.variadic-function-definition
int sum(int count, ...) {
  va_list args;
  va_start(args, count);
  va_end(args);
  return count;
}

struct Logger {
  // cert: variant appsec-review.sei-cert.cpp.dcl50-cpp.variadic-function-definition
  void log(const char* format, ...) const {
    (void)format;
  }
};

namespace detail {
// cert: variant appsec-review.sei-cert.cpp.dcl50-cpp.variadic-function-definition
static long count_all(long first,
                      ...) {
  return first;
}
}  // namespace detail

// cert: variant appsec-review.sei-cert.cpp.dcl50-cpp.variadic-function-definition
auto trailing(int count, ...) noexcept -> int { return count; }

// cert: exception:DCL50-CPP-EX2 appsec-review.sei-cert.cpp.dcl50-cpp.variadic-function-definition
int declared_only(int count, ...);

template <typename T>
class has_value {
  static std::true_type probe(const T*);
  // cert: exception:DCL50-CPP-EX2 appsec-review.sei-cert.cpp.dcl50-cpp.variadic-function-definition
  static std::false_type probe(...);
};

// cert: exception:DCL50-CPP-EX1 appsec-review.sei-cert.cpp.dcl50-cpp.variadic-function-definition
extern "C" int c_api_log(int level, ...) { return level; }

extern "C" {
// cert: exception:DCL50-CPP-EX1 appsec-review.sei-cert.cpp.dcl50-cpp.variadic-function-definition
int c_api_trace(int level, ...) { return level; }
}

// cert: safe-alternative appsec-review.sei-cert.cpp.dcl50-cpp.variadic-function-definition
template <typename... Values> int typed_sum(Values... values) { return (0 + ... + values); }

// cert: near-miss appsec-review.sei-cert.cpp.dcl50-cpp.variadic-function-definition
int handler() {
  try {
    return typed_sum(1, 2);
  } catch (...) {
    return 0;
  }
}

template <typename... Values>
// cert: near-miss appsec-review.sei-cert.cpp.dcl50-cpp.variadic-function-definition
void forward_all(Values... values) { (consume(values), ...); }

// cert: negative appsec-review.sei-cert.cpp.dcl50-cpp.variadic-function-definition
int fixed(int first, int second) { return first + second; }
