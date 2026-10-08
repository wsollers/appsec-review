#include <condition_variable>
#include <memory>
#include <mutex>
#include <pthread.h>
#include <string>
#include <string_view>
#include <vector>

std::shared_ptr<int> related(const std::shared_ptr<int>& owner) {
  return owner;
}

int array_match() {
  int* values = new int[2];
  values[0] = 1;
  delete[] values;
  return 1;
}

std::string owned_string() {
  return std::string(12, 'x');
}

std::vector<int> owned_container() {
  return {1, 2};
}

int predicate_wait() {
  std::mutex mutex;
  std::condition_variable condition;
  bool ready = false;
  std::unique_lock lock(mutex);
  condition.wait(lock, [&] { return ready; });
  return ready;
}

int scoped_lock() {
  std::mutex mutex;
  std::lock_guard guard(mutex);
  return 1;
}

int recursive_lock() {
  std::recursive_mutex mutex;
  std::lock_guard first(mutex);
  std::lock_guard second(mutex);
  return 1;
}

int destroy_unlocked_mutex() {
  pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
  return pthread_mutex_destroy(&mutex);
}
