// SEI CERT ERR52-CPP focused fixture.
#include <csetjmp>
#include <setjmp.h>
#include <stdexcept>

static std::jmp_buf checkpoint;

int guarded() {
  // cert: positive appsec-review.sei-cert.cpp.err52-cpp.nonlocal-jump
  if (setjmp(checkpoint) != 0) {
    return 1;
  }
  return 0;
}

[[noreturn]] void bail() {
  // cert: variant appsec-review.sei-cert.cpp.err52-cpp.nonlocal-jump
  std::longjmp(checkpoint, 1);
}

namespace posix_jump {
sigjmp_buf environment;
void restore() {
  // cert: variant appsec-review.sei-cert.cpp.err52-cpp.nonlocal-jump
  siglongjmp(environment, 1);
}
}  // namespace posix_jump

void fail_safely() {
  // cert: safe-alternative appsec-review.sei-cert.cpp.err52-cpp.nonlocal-jump
  throw std::runtime_error("unrecoverable");
}

struct Recorder {
  void setjmp_marker(int value) { (void)value; }
};

void record(Recorder& recorder) {
  // cert: near-miss appsec-review.sei-cert.cpp.err52-cpp.nonlocal-jump
  recorder.setjmp_marker(1);
}
