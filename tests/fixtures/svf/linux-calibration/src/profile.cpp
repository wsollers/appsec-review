#include "calibration/api.hpp"

namespace calibration {

#ifndef CALIBRATION_PROFILE
#define CALIBRATION_PROFILE 0
#endif

#ifndef CALIBRATION_PROFILE_NAME
#define CALIBRATION_PROFILE_NAME profile_default
#endif

namespace {

int profile_value(int value) {
  return value + CALIBRATION_PROFILE;
}

}

int CALIBRATION_PROFILE_NAME(int value) {
  return profile_value(value);
}

}
