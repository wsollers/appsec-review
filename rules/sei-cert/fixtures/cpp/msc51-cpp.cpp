// SEI CERT MSC51-CPP focused fixture.
#include <ctime>
#include <random>

unsigned default_seed() {
  // cert: positive appsec-review.sei-cert.cpp.msc51-cpp.predictably-seeded-engine
  std::mt19937 engine;
  return engine();
}

unsigned time_seed() {
  std::time_t now;
  // cert: variant appsec-review.sei-cert.cpp.msc51-cpp.predictably-seeded-engine
  std::mt19937_64 engine(std::time(&now));
  return static_cast<unsigned>(engine());
}

unsigned brace_time_seed() {
  // cert: variant appsec-review.sei-cert.cpp.msc51-cpp.predictably-seeded-engine
  std::minstd_rand engine{static_cast<unsigned>(std::time(nullptr))};
  return engine();
}

unsigned unparsed_time_seed() {
  // cert: known-false-negative appsec-review.sei-cert.cpp.msc51-cpp.predictably-seeded-engine
  std::mt19937 engine(std::time(nullptr));
  return engine();
}

unsigned cast_time_seed() {
  // cert: variant appsec-review.sei-cert.cpp.msc51-cpp.predictably-seeded-engine
  std::default_random_engine engine(static_cast<unsigned>(time(nullptr)));
  return engine();
}

unsigned device_seed() {
  std::random_device device;
  // cert: safe-alternative appsec-review.sei-cert.cpp.msc51-cpp.predictably-seeded-engine
  std::mt19937 engine(device());
  return engine();
}

unsigned seed_sequence() {
  std::random_device device;
  std::seed_seq sequence{device(), device(), device()};
  // cert: negative appsec-review.sei-cert.cpp.msc51-cpp.predictably-seeded-engine
  std::mt19937 engine(sequence);
  return engine();
}

unsigned distribution_only() {
  // cert: near-miss appsec-review.sei-cert.cpp.msc51-cpp.predictably-seeded-engine
  std::uniform_int_distribution<unsigned> distribution;
  return distribution.max();
}

unsigned constant_seed() {
  const unsigned fixed = 42;
  // cert: known-false-negative appsec-review.sei-cert.cpp.msc51-cpp.predictably-seeded-engine
  std::mt19937 engine(fixed);
  return engine();
}
