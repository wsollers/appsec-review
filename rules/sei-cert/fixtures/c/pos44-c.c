/* SEI CERT POS44-C focused fixture. */
#include <pthread.h>
#include <signal.h>

void stop_worker(pthread_t worker) {
  // cert: positive appsec-review.sei-cert.c.pos44-c.terminating-signal-to-thread
  pthread_kill(worker, SIGKILL);
}

int stop_worker_politely(pthread_t worker) {
  // cert: variant appsec-review.sei-cert.c.pos44-c.terminating-signal-to-thread
  return pthread_kill(worker, SIGTERM);
}

void wake_worker(pthread_t worker) {
  // cert: near-miss appsec-review.sei-cert.c.pos44-c.terminating-signal-to-thread
  pthread_kill(worker, SIGUSR1);
}

int cancel_worker(pthread_t worker) {
  // cert: safe-alternative appsec-review.sei-cert.c.pos44-c.terminating-signal-to-thread
  return pthread_cancel(worker);
}

int probe_worker(pthread_t worker) {
  // cert: negative appsec-review.sei-cert.c.pos44-c.terminating-signal-to-thread
  return pthread_kill(worker, 0);
}
