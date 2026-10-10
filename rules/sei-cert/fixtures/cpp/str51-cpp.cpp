// SEI CERT STR51-CPP focused fixture.
#include <cstdlib>
#include <string>

std::string home() {
  // cert: positive appsec-review.sei-cert.cpp.str51-cpp.string-from-null-pointer
  std::string value(std::getenv("HOME"));
  return value;
}

std::string shell() {
  // cert: variant appsec-review.sei-cert.cpp.str51-cpp.string-from-null-pointer
  return std::string(getenv("SHELL"));
}

std::string empty_marker() {
  // cert: variant appsec-review.sei-cert.cpp.str51-cpp.string-from-null-pointer
  std::string marker = nullptr;
  return marker;
}

std::string checked_home() {
  // cert: safe-alternative appsec-review.sei-cert.cpp.str51-cpp.string-from-null-pointer
  const char* value = std::getenv("HOME");
  return value != nullptr ? std::string(value) : std::string();
}

bool has_home() {
  // cert: near-miss appsec-review.sei-cert.cpp.str51-cpp.string-from-null-pointer
  const char* home = std::getenv("HOME");
  return home != nullptr;
}

std::string literal() {
  // cert: negative appsec-review.sei-cert.cpp.str51-cpp.string-from-null-pointer
  std::string value("HOME");
  return value;
}

std::string via_variable() {
  const char* value = std::getenv("PATH");
  // cert: known-false-negative appsec-review.sei-cert.cpp.str51-cpp.string-from-null-pointer
  return std::string(value);
}
