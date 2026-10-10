/* SEI CERT CON36-C focused fixture. */
#include <pthread.h>
#include <stdbool.h>

static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t ready_cond = PTHREAD_COND_INITIALIZER;
static bool ready;

void wait_once(void) {
  pthread_mutex_lock(&lock);
  if (!ready) {
    // cert: positive appsec-review.sei-cert.c.con36-c.condition-wait-outside-loop
    pthread_cond_wait(&ready_cond, &lock);
  }
  pthread_mutex_unlock(&lock);
}

int wait_timed_once(const struct timespec *deadline) {
  pthread_mutex_lock(&lock);
  // cert: variant appsec-review.sei-cert.c.con36-c.condition-wait-outside-loop
  int rc = pthread_cond_timedwait(&ready_cond, &lock, deadline);
  pthread_mutex_unlock(&lock);
  return rc;
}

void wait_loop(void) {
  pthread_mutex_lock(&lock);
  while (!ready) {
    // cert: safe-alternative appsec-review.sei-cert.c.con36-c.condition-wait-outside-loop
    pthread_cond_wait(&ready_cond, &lock);
  }
  pthread_mutex_unlock(&lock);
}

void wait_do_loop(void) {
  pthread_mutex_lock(&lock);
  do {
    // cert: negative appsec-review.sei-cert.c.con36-c.condition-wait-outside-loop
    pthread_cond_wait(&ready_cond, &lock);
  } while (!ready);
  pthread_mutex_unlock(&lock);
}

void signal_ready(void) {
  pthread_mutex_lock(&lock);
  ready = true;
  // cert: near-miss appsec-review.sei-cert.c.con36-c.condition-wait-outside-loop
  pthread_cond_signal(&ready_cond);
  pthread_mutex_unlock(&lock);
}
