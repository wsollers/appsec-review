// SEI CERT DCL58-CPP focused fixture.
#include <cstddef>
#include <functional>
#include <string>

struct Account {
  std::string id;
};

namespace std {
// cert: positive appsec-review.sei-cert.cpp.dcl58-cpp.standard-namespace-declaration
int project_counter = 0;

// cert: variant appsec-review.sei-cert.cpp.dcl58-cpp.standard-namespace-declaration
string describe(const Account& account) { return account.id; }

// cert: variant appsec-review.sei-cert.cpp.dcl58-cpp.standard-namespace-declaration
void reset_counters();

// cert: safe-alternative appsec-review.sei-cert.cpp.dcl58-cpp.standard-namespace-declaration
template <>
struct hash<Account> {
  // cert: negative appsec-review.sei-cert.cpp.dcl58-cpp.standard-namespace-declaration
  size_t operator()(const Account& account) const noexcept {
    return hash<string>()(account.id);
  }
};
}  // namespace std

namespace project {
// cert: near-miss appsec-review.sei-cert.cpp.dcl58-cpp.standard-namespace-declaration
int project_counter = 0;
}  // namespace project
