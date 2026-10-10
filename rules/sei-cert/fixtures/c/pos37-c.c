/* SEI CERT POS37-C focused fixture. */
#include <stdlib.h>
#include <unistd.h>

void drop_unchecked(void) {
  // cert: positive appsec-review.sei-cert.c.pos37-c.unchecked-privilege-drop
  setuid(getuid());
}

void drop_void_cast(void) {
  // cert: variant appsec-review.sei-cert.c.pos37-c.unchecked-privilege-drop
  (void)setgid(getgid());
}

void drop_checked(void) {
  // cert: safe-alternative appsec-review.sei-cert.c.pos37-c.unchecked-privilege-drop
  if (setuid(getuid()) != 0) {
    abort();
  }
}

int drop_returned(void) {
  // cert: negative appsec-review.sei-cert.c.pos37-c.unchecked-privilege-drop
  return setresuid(getuid(), getuid(), getuid());
}

void query_only(void) {
  // cert: near-miss appsec-review.sei-cert.c.pos37-c.unchecked-privilege-drop
  getuid();
}
