#include "calibration/api.hpp"
#include "calibration/platform.h"

#include <cstdlib>
#include <limits>

int main(int argc, char** argv) {
  if (argc != 2) {
    return 64;
  }
  const int mode = std::atoi(argv[1]);
  int result = 0;
  if (mode == 10 || mode == 110) {
    result = platform_shape(mode == 10 ? 10 : 0);
  } else {
    result = calibration::coordination_shape(mode);
  }
  const volatile int retained = result;
  return retained == std::numeric_limits<int>::min() ? 1 : 0;
}
