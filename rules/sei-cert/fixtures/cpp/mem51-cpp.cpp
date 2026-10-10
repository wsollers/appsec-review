// SEI CERT MEM51-CPP focused fixture.
#include <cstdlib>
#include <memory>

int scalar_delete() {
  // cert: positive appsec-review.sei-cert.cpp.mem51-cpp.array-new-scalar-delete
  int* values = new int[4];
  values[0] = 1;
  const int result = values[0];
  delete values;
  return result;
}

int deduced_pointer() {
  // cert: variant appsec-review.sei-cert.cpp.mem51-cpp.array-new-scalar-delete
  auto* values = new int[2]{4, 7};
  const int result = values[0];
  delete values;
  return result;
}

void unique_scalar() {
  // cert: variant appsec-review.sei-cert.cpp.mem51-cpp.array-new-scalar-delete
  std::unique_ptr<int> values(new int[8]);
}

int array_delete() {
  // cert: safe-alternative appsec-review.sei-cert.cpp.mem51-cpp.array-new-scalar-delete
  int* values = new int[4];
  const int result = values[0] = 2;
  delete[] values;
  return result;
}

void unique_array() {
  // cert: negative appsec-review.sei-cert.cpp.mem51-cpp.array-new-scalar-delete
  std::unique_ptr<int[]> values(new int[8]);
}

int scalar_pair() {
  // cert: near-miss appsec-review.sei-cert.cpp.mem51-cpp.array-new-scalar-delete
  int* value = new int(3);
  const int result = *value;
  delete value;
  return result;
}

void malloc_delete() {
  // cert: positive appsec-review.sei-cert.cpp.mem51-cpp.allocator-deallocator-mismatch
  int* value = static_cast<int*>(std::malloc(sizeof(int)));
  delete value;
}

void new_free() {
  // cert: variant appsec-review.sei-cert.cpp.mem51-cpp.allocator-deallocator-mismatch
  int* value = new int(5);
  std::free(value);
}

void malloc_free() {
  // cert: safe-alternative appsec-review.sei-cert.cpp.mem51-cpp.allocator-deallocator-mismatch
  int* value = static_cast<int*>(std::malloc(sizeof(int)));
  std::free(value);
}

void new_delete() {
  // cert: near-miss appsec-review.sei-cert.cpp.mem51-cpp.allocator-deallocator-mismatch
  int* value = new int(5);
  delete value;
}
