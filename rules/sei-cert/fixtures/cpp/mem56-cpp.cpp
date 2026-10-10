// SEI CERT MEM56-CPP focused fixture.
#include <memory>

std::shared_ptr<int> duplicate(const std::shared_ptr<int>& owner) {
  // cert: positive appsec-review.sei-cert.cpp.mem56-cpp.unrelated-smart-pointer-owner
  return std::shared_ptr<int>(owner.get());
}

void adopt(const std::unique_ptr<int>& owner) {
  // cert: variant appsec-review.sei-cert.cpp.mem56-cpp.unrelated-smart-pointer-owner
  std::unique_ptr<int> copy = owner.get();
  copy.release();
}

void reset_from(std::shared_ptr<int>& target, const std::shared_ptr<int>& owner) {
  // cert: variant appsec-review.sei-cert.cpp.mem56-cpp.unrelated-smart-pointer-owner
  target.reset(owner.get());
}

std::shared_ptr<int> share(const std::shared_ptr<int>& owner) {
  // cert: safe-alternative appsec-review.sei-cert.cpp.mem56-cpp.unrelated-smart-pointer-owner
  return owner;
}

int observe(const std::shared_ptr<int>& owner) {
  // cert: near-miss appsec-review.sei-cert.cpp.mem56-cpp.unrelated-smart-pointer-owner
  int* raw = owner.get();
  return *raw;
}

std::shared_ptr<int> through_alias(const std::shared_ptr<int>& owner) {
  int* raw = owner.get();
  // cert: known-false-negative appsec-review.sei-cert.cpp.mem56-cpp.unrelated-smart-pointer-owner
  return std::shared_ptr<int>(raw);
}
