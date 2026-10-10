// SEI CERT CON51-CPP focused fixture.
#include <mutex>
#include <stdexcept>

std::mutex state_mutex;
int state = 0;

void update(int value) {
  // cert: positive appsec-review.sei-cert.cpp.con51-cpp.manual-lock-before-throw
  state_mutex.lock();
  if (value < 0) {
    throw std::invalid_argument("negative");
  }
  state = value;
  state_mutex.unlock();
}

void update_in_try(int value) {
  try {
    // cert: variant appsec-review.sei-cert.cpp.con51-cpp.manual-lock-before-throw
    state_mutex.lock();
    throw std::runtime_error("x");
  } catch (const std::runtime_error&) {
  }
}

void balanced(int value) {
  // cert: near-miss appsec-review.sei-cert.cpp.con51-cpp.manual-lock-before-throw
  state_mutex.lock();
  state = value;
  state_mutex.unlock();
}

void unlock_first(int value) {
  // cert: safe-alternative appsec-review.sei-cert.cpp.con51-cpp.manual-lock-before-throw
  state_mutex.lock();
  state = value;
  state_mutex.unlock();
  throw std::runtime_error("after release");
}

void scoped(int value) {
  // cert: negative appsec-review.sei-cert.cpp.con51-cpp.manual-lock-before-throw
  std::lock_guard<std::mutex> guard(state_mutex);
  if (value < 0) {
    throw std::invalid_argument("negative");
  }
}

void validate(int value);
void indirect(int value) {
  // cert: known-false-negative appsec-review.sei-cert.cpp.con51-cpp.manual-lock-before-throw
  state_mutex.lock();
  validate(value);
  state_mutex.unlock();
}
