// Fixture for the C/C++ memory-safety review-signal rules: nothing here may be reported.
#include <algorithm>
#include <cstdint>
#include <cstdlib>
#include <cstring>

struct Header {
  std::uint16_t length;
  char name[16];
};

int copy_clamped(const std::uint8_t *data, Header &out) {
  out.length = static_cast<std::uint16_t>(data[0] | (data[1] << 8));
  std::memcpy(out.name, data + 2, std::min<std::size_t>(out.length, sizeof(out.name)));
  return 0;
}

int copy_sized(const std::uint8_t *data, Header &out) {
  std::memcpy(out.name, data + 2, sizeof(out.name));
  std::memcpy(out.name, data + 2, 8);
  return 0;
}

void *size_widened(std::uint32_t width, std::uint32_t height) {
  std::size_t bytes = static_cast<std::size_t>(width) * height * 4;
  return std::malloc(bytes);
}

int sum(int a, int b) {
  int total = a * b;
  return total;
}
