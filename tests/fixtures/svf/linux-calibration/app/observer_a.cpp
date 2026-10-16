#include "calibration/api.hpp"

#include <cstdlib>
#include <limits>
#include <memory>
#include <stdexcept>

namespace {

int run(int mode) {
  switch (mode) {
    case 1: {
      int* value = calibration::open_slot();
      calibration::close_slot(value);
      return calibration::read_slot(value);
    }
    case 2: return static_cast<unsigned char>(calibration::text_view().front());
    case 3: return *calibration::position_view();
    case 4: {
      auto first = std::make_shared<int>(31);
      auto second = calibration::unrelated_owner(first);
      return *second;
    }
    case 5: return calibration::array_shape();
    case 6: return calibration::scaled_shape(16385);
    case 7: return calibration::placement_shape(true);
    case 8: return calibration::duration_shape(true);
    case 9: return calibration::template_shape(9);
    case 10: return calibration::indirect_shape(9);
    case 20: return calibration::profile_alpha(1) + calibration::profile_beta(1);
    case 101: {
      int* value = calibration::open_slot();
      const int result = calibration::read_slot(value);
      calibration::close_slot(value);
      return result;
    }
    case 102: {
      const std::string value(96, 'x');
      return static_cast<unsigned char>(std::string_view(value).front());
    }
    case 103: {
      const std::vector<int> values{3, 5, 8};
      return *values.cbegin();
    }
    case 104: {
      auto first = std::make_shared<int>(31);
      auto second = calibration::related_owner(first);
      return *second;
    }
    case 105: {
      auto values = std::make_unique<int[]>(2);
      values[0] = 4;
      return values[0];
    }
    case 106: return calibration::scaled_shape(2);
    case 107: return calibration::placement_shape(false);
    case 108: return calibration::duration_shape(false);
    default: return 0;
  }
}

}

int main(int argc, char** argv) {
  if (argc != 2) {
    return 64;
  }
  const volatile int result = run(std::atoi(argv[1]));
  return result == std::numeric_limits<int>::min() ? 1 : 0;
}
