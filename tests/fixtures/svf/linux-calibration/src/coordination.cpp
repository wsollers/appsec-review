#include "calibration/api.hpp"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <mutex>
#include <stdexcept>
#include <thread>

namespace calibration {
namespace {

int shared_value = 0;
struct Flags {
  unsigned int first : 2;
  unsigned int second : 2;
};
Flags shared_flags{};

std::timed_mutex first_lock;
std::timed_mutex second_lock;
std::timed_mutex retained_lock;
std::mutex condition_lock;
std::condition_variable condition;
bool event_ready = false;
std::atomic<int> ready{0};
std::atomic<bool> start{false};
std::atomic<int> published{0};
int payload = 0;
thread_local const int* local_address = nullptr;

void await_start() {
  ready.fetch_add(1, std::memory_order_relaxed);
  while (!start.load(std::memory_order_acquire)) {
    std::this_thread::yield();
  }
}

int shared_updates(bool bit_fields) {
  ready.store(0, std::memory_order_relaxed);
  start.store(false, std::memory_order_relaxed);
  auto left = std::thread([bit_fields] {
    await_start();
    for (int index = 0; index < 20000; ++index) {
      if (bit_fields) {
        shared_flags.first = static_cast<unsigned int>(index) & 3U;
      } else {
        ++shared_value;
      }
    }
  });
  auto right = std::thread([bit_fields] {
    await_start();
    for (int index = 0; index < 20000; ++index) {
      if (bit_fields) {
        shared_flags.second = static_cast<unsigned int>(index + 1) & 3U;
      } else {
        ++shared_value;
      }
    }
  });
  while (ready.load(std::memory_order_relaxed) != 2) {
    std::this_thread::yield();
  }
  start.store(true, std::memory_order_release);
  left.join();
  right.join();
  return bit_fields ? static_cast<int>(shared_flags.first + shared_flags.second) : shared_value;
}

int ordered_updates() {
  std::mutex lock;
  int value = 0;
  auto work = [&] {
    for (int index = 0; index < 20000; ++index) {
      std::lock_guard guard(lock);
      ++value;
    }
  };
  std::thread left(work);
  std::thread right(work);
  left.join();
  right.join();
  return value;
}

int reversed_order() {
  std::atomic<int> failures{0};
  auto left = std::thread([&] {
    std::lock_guard guard(first_lock);
    if (!second_lock.try_lock_for(std::chrono::milliseconds(20))) {
      failures.fetch_add(1, std::memory_order_relaxed);
    } else {
      second_lock.unlock();
    }
  });
  auto right = std::thread([&] {
    std::lock_guard guard(second_lock);
    if (!first_lock.try_lock_for(std::chrono::milliseconds(20))) {
      failures.fetch_add(1, std::memory_order_relaxed);
    } else {
      first_lock.unlock();
    }
  });
  left.join();
  right.join();
  return failures.load(std::memory_order_relaxed);
}

int consistent_order() {
  int value = 0;
  auto work = [&] {
    std::scoped_lock guard(first_lock, second_lock);
    ++value;
  };
  std::thread left(work);
  std::thread right(work);
  left.join();
  right.join();
  return value;
}

int missed_event() {
  condition.notify_one();
  std::unique_lock lock(condition_lock);
  return condition.wait_for(lock, std::chrono::milliseconds(20)) == std::cv_status::timeout ? 1 : 0;
}

int predicate_event() {
  event_ready = false;
  std::thread notifier([] {
    {
      std::lock_guard guard(condition_lock);
      event_ready = true;
    }
    condition.notify_one();
  });
  std::unique_lock lock(condition_lock);
  condition.wait(lock, [] { return event_ready; });
  notifier.join();
  return event_ready ? 1 : 0;
}

int retained_after_throw() {
  try {
    retained_lock.lock();
    throw std::runtime_error("x");
  } catch (const std::runtime_error&) {
  }
  const bool acquired = retained_lock.try_lock_for(std::chrono::milliseconds(20));
  if (acquired) {
    retained_lock.unlock();
  }
  return acquired ? 0 : 1;
}

int scoped_throw() {
  try {
    std::unique_lock guard(retained_lock);
    throw std::runtime_error("x");
  } catch (const std::runtime_error&) {
  }
  const bool acquired = retained_lock.try_lock_for(std::chrono::milliseconds(20));
  if (acquired) {
    retained_lock.unlock();
  }
  return acquired ? 1 : 0;
}

int repeated_lock() {
  std::timed_mutex lock;
  lock.lock();
  const bool acquired = lock.try_lock_for(std::chrono::milliseconds(20));
  if (acquired) {
    lock.unlock();
  }
  lock.unlock();
  return acquired ? 0 : 1;
}

int recursive_lock() {
  std::recursive_mutex lock;
  std::lock_guard first(lock);
  std::lock_guard second(lock);
  return 1;
}

int invalid_transition() {
  std::thread worker;
  try {
    worker.join();
  } catch (const std::system_error&) {
    return 1;
  }
  return 0;
}

int valid_transition() {
  std::thread worker([] {});
  if (worker.joinable()) {
    worker.join();
    return 1;
  }
  return 0;
}

int local_duration() {
  int value = 23;
  local_address = &value;
  const int before = *local_address;
  {
    int replacement = 29;
    local_address = &replacement;
  }
  return before + *local_address;
}

int local_value() {
  int value = 23;
  const int retained = value;
  return retained;
}

int relaxed_publication() {
  published.store(0, std::memory_order_relaxed);
  payload = 0;
  std::thread writer([] {
    payload = 37;
    published.store(1, std::memory_order_relaxed);
  });
  std::thread reader([] {
    while (published.load(std::memory_order_relaxed) == 0) {
      std::this_thread::yield();
    }
    shared_value = payload;
  });
  writer.join();
  reader.join();
  return shared_value;
}

int ordered_publication() {
  published.store(0, std::memory_order_relaxed);
  payload = 0;
  std::thread writer([] {
    payload = 37;
    published.store(1, std::memory_order_release);
  });
  std::thread reader([] {
    while (published.load(std::memory_order_acquire) == 0) {
      std::this_thread::yield();
    }
    shared_value = payload;
  });
  writer.join();
  reader.join();
  return shared_value;
}

}

int coordination_shape(int mode) {
  switch (mode) {
    case 1: return shared_updates(false);
    case 2: return shared_updates(true);
    case 3: return reversed_order();
    case 4: return missed_event();
    case 5: return retained_after_throw();
    case 6: return repeated_lock();
    case 7: return invalid_transition();
    case 8: return local_duration();
    case 9: return relaxed_publication();
    case 101: return ordered_updates();
    case 102: return ordered_updates();
    case 103: return consistent_order();
    case 104: return predicate_event();
    case 105: return scoped_throw();
    case 106: return recursive_lock();
    case 107: return valid_transition();
    case 108: return local_value();
    case 109: return ordered_publication();
    default: return 0;
  }
}

}
