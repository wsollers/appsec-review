/* SEI CERT POS47-C focused fixture. */
#include <pthread.h>

void *worker(void *arg) {
  int previous;
  // cert: positive appsec-review.sei-cert.c.pos47-c.asynchronous-cancellation
  pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, &previous);
  return arg;
}

void *checked_worker(void *arg) {
  int previous;
  // cert: variant appsec-review.sei-cert.c.pos47-c.asynchronous-cancellation
  if (pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, &previous) != 0) {
    return NULL;
  }
  return arg;
}

void *deferred_worker(void *arg) {
  int previous;
  // cert: safe-alternative appsec-review.sei-cert.c.pos47-c.asynchronous-cancellation
  pthread_setcanceltype(PTHREAD_CANCEL_DEFERRED, &previous);
  return arg;
}

void *state_worker(void *arg) {
  int previous;
  // cert: near-miss appsec-review.sei-cert.c.pos47-c.asynchronous-cancellation
  pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, &previous);
  return arg;
}

void *variable_worker(void *arg, int type) {
  int previous;
  // cert: known-false-negative appsec-review.sei-cert.c.pos47-c.asynchronous-cancellation
  pthread_setcanceltype(type, &previous);
  return arg;
}
