// SEI CERT EXP54-CPP focused fixture (escaping references to locals).
#include <string>
#include <string_view>
#include <vector>

std::string_view text_view() {
  std::string value(96, 'x');
  // cert: positive appsec-review.sei-cert.cpp.exp54-cpp.escaping-reference-to-local
  return std::string_view(value);
}

std::string_view implicit_view() {
  std::string value = "temporary";
  // cert: variant appsec-review.sei-cert.cpp.exp54-cpp.escaping-reference-to-local
  return value;
}

const char* raw_text() {
  std::string value{"buffer"};
  // cert: variant appsec-review.sei-cert.cpp.exp54-cpp.escaping-reference-to-local
  return value.c_str();
}

std::vector<int>::const_iterator position_view() {
  std::vector<int> values{3, 5, 8};
  // cert: variant appsec-review.sei-cert.cpp.exp54-cpp.escaping-reference-to-local
  return values.cbegin();
}

std::string owned_copy() {
  std::string value(16, 'y');
  // cert: safe-alternative appsec-review.sei-cert.cpp.exp54-cpp.escaping-reference-to-local
  return value;
}

std::string copy_from_pointer() {
  std::string value("abc");
  // cert: near-miss appsec-review.sei-cert.cpp.exp54-cpp.escaping-reference-to-local
  return value.c_str();
}

std::string_view parameter_view(const std::string& value) {
  // cert: negative appsec-review.sei-cert.cpp.exp54-cpp.escaping-reference-to-local
  return std::string_view(value);
}

std::string_view static_view() {
  static std::string value = "persistent";
  // cert: negative appsec-review.sei-cert.cpp.exp54-cpp.escaping-reference-to-local
  return std::string_view(value);
}
