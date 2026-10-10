// SEI CERT CON56-CPP focused fixture.
#include <chrono>
#include <mutex>

std::timed_mutex shared_lock;

int repeated_lock() {
  std::timed_mutex lock;
  // cert: positive appsec-review.sei-cert.cpp.con56-cpp.relock-owned-nonrecursive-mutex
  lock.lock();
  const bool acquired = lock.try_lock_for(std::chrono::milliseconds(20));
  lock.unlock();
  return acquired;
}

void relock_global() {
  // cert: variant appsec-review.sei-cert.cpp.con56-cpp.relock-owned-nonrecursive-mutex
  shared_lock.lock();
  shared_lock.try_lock();
}

void release_then_try() {
  // cert: safe-alternative appsec-review.sei-cert.cpp.con56-cpp.relock-owned-nonrecursive-mutex
  shared_lock.lock();
  shared_lock.unlock();
  shared_lock.try_lock();
}

void first_function() {
  // cert: near-miss appsec-review.sei-cert.cpp.con56-cpp.relock-owned-nonrecursive-mutex
  shared_lock.lock();
}

void second_function() {
  // cert: negative appsec-review.sei-cert.cpp.con56-cpp.relock-owned-nonrecursive-mutex
  shared_lock.try_lock();
}

int recursive_ok() {
  std::recursive_mutex lock;
  // cert: negative appsec-review.sei-cert.cpp.con56-cpp.relock-owned-nonrecursive-mutex
  lock.lock();
  lock.lock();
  lock.unlock();
  lock.unlock();
  return 1;
}
