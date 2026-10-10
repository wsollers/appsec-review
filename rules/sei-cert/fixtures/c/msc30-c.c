/* SEI CERT MSC30-C focused fixture. */
#include <stdlib.h>
#include <sys/random.h>

int session_token(void) {
  // cert: positive appsec-review.sei-cert.c.msc30-c.rand-call
  return rand();
}

int dice(void) {
  // cert: variant appsec-review.sei-cert.c.msc30-c.rand-call
  return 1 + (rand() % 6);
}

int strong_token(unsigned int *value) {
  // cert: safe-alternative appsec-review.sei-cert.c.msc30-c.rand-call
  return getrandom(value, sizeof *value, 0) == sizeof *value ? 0 : -1;
}

int rand_r_state(unsigned int *state);
int reentrant(unsigned int *state) {
  // cert: near-miss appsec-review.sei-cert.c.msc30-c.rand-call
  return rand_r_state(state);
}

long seeded(void) {
  // cert: negative appsec-review.sei-cert.c.msc30-c.rand-call
  return random();
}
