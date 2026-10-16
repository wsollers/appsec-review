#include "calibration/platform.h"

#include <pthread.h>

int platform_shape(int mode) {
  pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
  if (mode == 10) {
    if (pthread_mutex_lock(&lock) != 0) {
      return 0;
    }
    return pthread_mutex_destroy(&lock);
  }
  if (pthread_mutex_destroy(&lock) != 0) {
    return 0;
  }
  return 1;
}
