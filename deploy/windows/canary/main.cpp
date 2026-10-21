// Repository-owned canary for the Windows build toolchain. It is built, never run: readiness only needs to
// know that the compiler, linker, runtime libraries and sanitizer runtime resolve.
#include <cstdio>
#include <cstring>

int main(int argc, char **argv) {
  char buffer[16];
  std::snprintf(buffer, sizeof buffer, "%d", argc);
  return static_cast<int>(std::strlen(buffer)) + (argv != nullptr ? 0 : 1);
}
