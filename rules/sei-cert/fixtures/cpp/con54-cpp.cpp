// SEI CERT CON54-CPP focused fixture.
#include <chrono>
#include <condition_variable>
#include <mutex>

std::mutex mutex;
std::condition_variable condition;
bool ready = false;

void wait_once() {
  std::unique_lock<std::mutex> lock(mutex);
  // cert: positive appsec-review.sei-cert.cpp.con54-cpp.predicate-free-wait-outside-loop
  condition.wait(lock);
}

bool wait_briefly() {
  std::unique_lock<std::mutex> lock(mutex);
  // cert: variant appsec-review.sei-cert.cpp.con54-cpp.predicate-free-wait-outside-loop
  return condition.wait_for(lock, std::chrono::milliseconds(20)) == std::cv_status::timeout;
}

void wait_with_predicate() {
  std::unique_lock<std::mutex> lock(mutex);
  // cert: safe-alternative appsec-review.sei-cert.cpp.con54-cpp.predicate-free-wait-outside-loop
  condition.wait(lock, [] { return ready; });
}

void wait_in_loop() {
  std::unique_lock<std::mutex> lock(mutex);
  while (!ready) {
    // cert: negative appsec-review.sei-cert.cpp.con54-cpp.predicate-free-wait-outside-loop
    condition.wait(lock);
  }
}

void wait_in_do_loop() {
  std::unique_lock<std::mutex> lock(mutex);
  do {
    // cert: negative appsec-review.sei-cert.cpp.con54-cpp.predicate-free-wait-outside-loop
    condition.wait(lock);
  } while (!ready);
}

void notify() {
  // cert: near-miss appsec-review.sei-cert.cpp.con54-cpp.predicate-free-wait-outside-loop
  condition.notify_one();
}
