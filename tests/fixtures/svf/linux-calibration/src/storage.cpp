#include "calibration/api.hpp"

#include <cstdlib>

namespace calibration {

int* open_slot() {
  auto* value = static_cast<int*>(std::malloc(sizeof(int)));
  if (value != nullptr) {
    *value = 41;
  }
  return value;
}

void close_slot(int* value) {
  std::free(value);
}

int read_slot(const int* value) {
  return value == nullptr ? 0 : *value;
}

}
