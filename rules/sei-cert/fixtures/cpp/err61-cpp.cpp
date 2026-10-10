// SEI CERT ERR61-CPP focused fixture.
#include <stdexcept>
#include <string>

namespace app {
struct Error : std::runtime_error {
  using std::runtime_error::runtime_error;
};
void work();

int by_value() {
  try {
    work();
  // cert: positive appsec-review.sei-cert.cpp.err61-cpp.catch-by-value
  } catch (std::exception error) {
    return 1;
  }
  return 0;
}

int by_const_value() {
  try {
    work();
  // cert: variant appsec-review.sei-cert.cpp.err61-cpp.catch-by-value
  } catch (const Error error) {
    return 1;
  }
  return 0;
}

int by_reference() {
  try {
    work();
  // cert: safe-alternative appsec-review.sei-cert.cpp.err61-cpp.catch-by-value
  } catch (const std::exception& error) {
    return 1;
  }
  return 0;
}

int by_mutable_reference() {
  try {
    work();
  // cert: negative appsec-review.sei-cert.cpp.err61-cpp.catch-by-value
  } catch (Error& error) {
    return 1;
  }
  return 0;
}

int scalar_code() {
  try {
    work();
  // cert: near-miss appsec-review.sei-cert.cpp.err61-cpp.catch-by-value
  } catch (int code) {
    return code;
  }
  return 0;
}

int pointer_payload() {
  try {
    work();
  // cert: near-miss appsec-review.sei-cert.cpp.err61-cpp.catch-by-value
  } catch (const char* text) {
    return text != nullptr;
  }
  return 0;
}

int catch_all() {
  try {
    work();
  // cert: negative appsec-review.sei-cert.cpp.err61-cpp.catch-by-value
  } catch (...) {
    return 1;
  }
  return 0;
}
}  // namespace app
