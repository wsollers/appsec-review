/* SEI CERT CON31-C focused fixture. */
#include <pthread.h>
#include <threads.h>

int destroy_while_locked(void) {
  pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
  pthread_mutex_lock(&lock);
  // cert: positive appsec-review.sei-cert.c.con31-c.destroy-locked-mutex
  return pthread_mutex_destroy(&lock);
}

int destroy_after_checked_lock(void) {
  pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
  if (pthread_mutex_lock(&lock) != 0) {
    return 0;
  }
  // cert: variant appsec-review.sei-cert.c.con31-c.destroy-locked-mutex
  return pthread_mutex_destroy(&lock);
}

void destroy_c11(mtx_t *unused) {
  mtx_t lock;
  mtx_init(&lock, mtx_plain);
  int rc = mtx_lock(&lock);
  (void)rc;
  // cert: variant appsec-review.sei-cert.c.con31-c.destroy-locked-mutex
  mtx_destroy(&lock);
}

int destroy_after_unlock(void) {
  pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
  pthread_mutex_lock(&lock);
  pthread_mutex_unlock(&lock);
  // cert: safe-alternative appsec-review.sei-cert.c.con31-c.destroy-locked-mutex
  return pthread_mutex_destroy(&lock);
}

int destroy_never_locked(int mode) {
  pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
  if (mode == 10) {
    if (pthread_mutex_lock(&lock) != 0) {
      return 0;
    }
    pthread_mutex_unlock(&lock);
  }
  // cert: near-miss appsec-review.sei-cert.c.con31-c.destroy-locked-mutex
  return pthread_mutex_destroy(&lock);
}

int destroy_other(pthread_mutex_t *first, pthread_mutex_t *second) {
  pthread_mutex_lock(first);
  // cert: negative appsec-review.sei-cert.c.con31-c.destroy-locked-mutex
  return pthread_mutex_destroy(second);
}
