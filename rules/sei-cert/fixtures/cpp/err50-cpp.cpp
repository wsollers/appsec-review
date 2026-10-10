// SEI CERT ERR50-CPP focused fixture.
#include <cstdlib>
#include <iostream>
#include <stdexcept>

void fail_fast() {
  // cert: positive appsec-review.sei-cert.cpp.err50-cpp.abrupt-termination-call
  std::abort();
}

void quick() {
  // cert: variant appsec-review.sei-cert.cpp.err50-cpp.abrupt-termination-call
  std::quick_exit(1);
}

void immediate() {
  // cert: variant appsec-review.sei-cert.cpp.err50-cpp.abrupt-termination-call
  _Exit(2);
}

void critical_error() {
  std::cerr << "unrecoverable configuration state; terminating\n";
  // cert: unmodeled-exception:ERR50-CPP-EX1 appsec-review.sei-cert.cpp.err50-cpp.abrupt-termination-call
  std::abort();
}

void report() {
  // cert: safe-alternative appsec-review.sei-cert.cpp.err50-cpp.abrupt-termination-call
  throw std::runtime_error("report to caller");
}

struct Job {
  void abort() {}
};

void cancel(Job& job) {
  // cert: near-miss appsec-review.sei-cert.cpp.err50-cpp.abrupt-termination-call
  job.abort();
}
