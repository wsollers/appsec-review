#include <chrono>
#include <condition_variable>
#include <memory>
#include <mutex>
#include <pthread.h>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

std::shared_ptr<int> unrelated(const std::shared_ptr<int>& owner) {
  return std::shared_ptr<int>(owner.get());
}

int array_mismatch() {
  int* values = new int[2];
  values[0] = 1;
  delete values;
  return 1;
}

std::string_view local_view() {
  std::string value(12, 'x');
  return std::string_view(value);
}

std::vector<int>::const_iterator local_iterator() {
  std::vector<int> values{1, 2};
  return values.cbegin();
}

int predicate_free_wait() {
  std::mutex mutex;
  std::condition_variable condition;
  std::unique_lock lock(mutex);
  return condition.wait_for(lock, std::chrono::milliseconds(1)) == std::cv_status::timeout;
}

int lock_then_throw() {
  std::timed_mutex mutex;
  try {
    mutex.lock();
    throw std::runtime_error("x");
  } catch (const std::runtime_error&) {
  }
  return 1;
}

int repeat_lock() {
  std::timed_mutex mutex;
  mutex.lock();
  const bool acquired = mutex.try_lock_for(std::chrono::milliseconds(1));
  mutex.unlock();
  return acquired;
}

int destroy_locked_mutex() {
  pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
  pthread_mutex_lock(&mutex);
  return pthread_mutex_destroy(&mutex);
}
