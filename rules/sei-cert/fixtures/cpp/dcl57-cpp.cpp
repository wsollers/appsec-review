// SEI CERT DCL57-CPP focused fixture.
#include <stdexcept>

class Connection {
 public:
  ~Connection() {
    if (open_) {
      // cert: positive appsec-review.sei-cert.cpp.dcl57-cpp.throw-in-destructor
      throw std::runtime_error("still open");
    }
  }
  bool open_ = false;
};

class File {
 public:
  ~File();
  bool dirty_ = false;
};

File::~File() {
  if (dirty_) {
    // cert: variant appsec-review.sei-cert.cpp.dcl57-cpp.throw-in-destructor
    throw std::logic_error("unsaved");
  }
}

class Guarded {
 public:
  ~Guarded() {
    try {
      // cert: safe-alternative appsec-review.sei-cert.cpp.dcl57-cpp.throw-in-destructor
      throw std::runtime_error("handled locally");
    } catch (...) {
    }
  }
};

class Builder {
 public:
  void finish() {
    // cert: near-miss appsec-review.sei-cert.cpp.dcl57-cpp.throw-in-destructor
    throw std::runtime_error("not finished");
  }
};

void release();
class Indirect {
 public:
  // cert: known-false-negative appsec-review.sei-cert.cpp.dcl57-cpp.throw-in-destructor
  ~Indirect() { release(); }
};
