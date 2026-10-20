// Fixture for the C/C++ memory-safety review-signal rules: every marked line must be reported.
#include <cstdint>
#include <cstdlib>
#include <cstring>

struct Header {
  std::uint16_t length;
  char name[16];
};

int copy_unbounded(const std::uint8_t *data, Header &out) {
  out.length = static_cast<std::uint16_t>(data[0] | (data[1] << 8));
  std::memcpy(out.name, data + 2, out.length);  // EXPECT cpp-copy-length-not-bounded
  return 0;
}

int move_unbounded(char *dst, const char *src, std::size_t count) {
  memmove(dst, src, count);  // EXPECT cpp-copy-length-not-bounded
  return 0;
}

void *size_wraps(std::uint32_t width, std::uint32_t height) {
  std::uint32_t bytes = width * height * 4;  // EXPECT cpp-narrow-size-product
  return std::malloc(bytes);  // EXPECT cpp-allocation-size-from-narrow-product
}

const char api_key_not_this_rule[] = "kept out of scope: secrets are the gitleaks rule's job";
