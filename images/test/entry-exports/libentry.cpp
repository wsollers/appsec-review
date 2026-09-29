// Fixture for scripts/smoke_entry_exports.sh (brief Q3). Harmless: no I/O, no network.
// entry_parse   exported (default visibility)          -> must be an exported-symbol root
// helper_static internal linkage                        -> must NOT be a root
// helper_hidden hidden visibility                       -> must NOT be a root
// fx::overload  two exported overloads, one qualified name -> ambiguous-export, no entry
#include <cstring>

static int sink_copy(char *dst, const char *src) {
  std::strcpy(dst, src);
  return 0;
}

static int helper_static(const char *s) {
  char buf[16];
  return sink_copy(buf, s);
}

__attribute__((visibility("hidden"))) int only_from_hidden(const char *s) {
  return s[0];
}

__attribute__((visibility("hidden"))) int helper_hidden(const char *s) {
  return only_from_hidden(s);
}

namespace fx {
__attribute__((visibility("default"))) int overload(int value) { return value + 1; }
__attribute__((visibility("default"))) int overload(const char *s) { return s[0]; }
}

extern "C" __attribute__((visibility("default"))) int entry_parse(const char *s) {
  return helper_static(s);
}
