// SEI CERT CON50-CPP focused fixture.
#include <pthread.h>

int destroy_while_locked() {
  pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
  pthread_mutex_lock(&lock);
  // cert: positive appsec-review.sei-cert.cpp.con50-cpp.destroy-locked-mutex
  return pthread_mutex_destroy(&lock);
}

int destroy_after_checked_lock() {
  pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
  if (pthread_mutex_lock(&lock) != 0) {
    return 0;
  }
  // cert: variant appsec-review.sei-cert.cpp.con50-cpp.destroy-locked-mutex
  return pthread_mutex_destroy(&lock);
}

int destroy_after_unlock() {
  pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
  pthread_mutex_lock(&lock);
  pthread_mutex_unlock(&lock);
  // cert: safe-alternative appsec-review.sei-cert.cpp.con50-cpp.destroy-locked-mutex
  return pthread_mutex_destroy(&lock);
}

int destroy_unlocked() {
  pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
  // cert: near-miss appsec-review.sei-cert.cpp.con50-cpp.destroy-locked-mutex
  return pthread_mutex_destroy(&lock);
}
