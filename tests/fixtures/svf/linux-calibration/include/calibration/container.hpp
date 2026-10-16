#pragma once

#include <array>
#include <cstddef>

namespace calibration {

template <std::size_t N>
class Container {
 public:
  int select(std::size_t index) const {
    return values_[index];
  }

  int select_checked(std::size_t index) const {
    return values_.at(index);
  }

 private:
  std::array<int, N> values_{};
};

}
