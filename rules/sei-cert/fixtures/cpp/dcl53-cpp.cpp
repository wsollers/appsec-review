// SEI CERT DCL53-CPP focused fixture.
#include <mutex>
#include <shared_mutex>

std::mutex counter_mutex;
std::shared_mutex table_mutex;
int counter = 0;

void increment() {
  // cert: positive appsec-review.sei-cert.cpp.dcl53-cpp.unnamed-lock-temporary
  std::unique_lock<std::mutex>(counter_mutex);
  ++counter;
}

void read_table() {
  // cert: variant appsec-review.sei-cert.cpp.dcl53-cpp.unnamed-lock-temporary
  std::shared_lock<std::shared_mutex>(table_mutex);
}

void deduced() {
  // cert: variant appsec-review.sei-cert.cpp.dcl53-cpp.unnamed-lock-temporary
  std::lock_guard(counter_mutex);
}

void named_lock() {
  // cert: safe-alternative appsec-review.sei-cert.cpp.dcl53-cpp.unnamed-lock-temporary
  std::lock_guard<std::mutex> guard(counter_mutex);
  ++counter;
}

void braced_lock() {
  // cert: negative appsec-review.sei-cert.cpp.dcl53-cpp.unnamed-lock-temporary
  std::scoped_lock guard{counter_mutex};
  ++counter;
}

void manual() {
  // cert: near-miss appsec-review.sei-cert.cpp.dcl53-cpp.unnamed-lock-temporary
  counter_mutex.lock();
  counter_mutex.unlock();
}
