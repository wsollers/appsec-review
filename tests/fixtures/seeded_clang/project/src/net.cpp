#include "util.h"
static void log_event(int code) { (void)code; }
int handle_packet(const char *pkt, int n) {
  char buf[32];
  log_event(n);
  int r = copy_field(buf, pkt, n);
  if (r < 0) return r;
  return buf[0];
}
