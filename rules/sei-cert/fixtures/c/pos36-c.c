/* SEI CERT POS36-C focused fixture. */
#include <stdlib.h>
#include <unistd.h>

void drop_wrong_order(void) {
  // cert: positive appsec-review.sei-cert.c.pos36-c.user-before-group-revocation
  if (setuid(getuid()) == -1) {
    abort();
  }
  if (setgid(getgid()) == -1) {
    abort();
  }
}

void drop_wrong_order_effective(void) {
  // cert: variant appsec-review.sei-cert.c.pos36-c.user-before-group-revocation
  // cert: variant appsec-review.sei-cert.c.pos37-c.unchecked-privilege-drop
  seteuid(getuid());
  // cert: variant appsec-review.sei-cert.c.pos37-c.unchecked-privilege-drop
  setegid(getgid());
}

void drop_correct_order(void) {
  // cert: safe-alternative appsec-review.sei-cert.c.pos36-c.user-before-group-revocation
  if (setgid(getgid()) == -1) {
    abort();
  }
  if (setuid(getuid()) == -1) {
    abort();
  }
}

void user_only(void) {
  // cert: near-miss appsec-review.sei-cert.c.pos36-c.user-before-group-revocation
  if (setuid(getuid()) == -1) {
    abort();
  }
}

static void drop_group(void) {
  if (setgid(getgid()) == -1) {
    abort();
  }
}

void split_across_functions(void) {
  // cert: known-false-negative appsec-review.sei-cert.c.pos36-c.user-before-group-revocation
  if (setuid(getuid()) == -1) {
    abort();
  }
  drop_group();
}
