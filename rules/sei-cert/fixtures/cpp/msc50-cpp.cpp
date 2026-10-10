// SEI CERT MSC50-CPP focused fixture.
#include <cstdlib>
#include <random>

int token() {
  // cert: positive appsec-review.sei-cert.cpp.msc50-cpp.rand-call
  return std::rand();
}

int legacy() {
  // cert: variant appsec-review.sei-cert.cpp.msc50-cpp.rand-call
  return 1 + rand() % 6;
}

int global_scope() {
  // cert: variant appsec-review.sei-cert.cpp.msc50-cpp.rand-call
  return ::rand();
}

unsigned modern() {
  std::random_device device;
  // cert: safe-alternative appsec-review.sei-cert.cpp.msc50-cpp.rand-call
  std::uniform_int_distribution<unsigned> distribution(0, 99);
  return distribution(device);
}

struct Dice {
  int rand() const { return 4; }
};

int member(const Dice& dice) {
  // cert: near-miss appsec-review.sei-cert.cpp.msc50-cpp.rand-call
  return dice.rand();
}
