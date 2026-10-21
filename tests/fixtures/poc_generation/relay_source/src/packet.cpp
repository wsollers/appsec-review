#include "relay/relay.hpp"

#include <cstring>

namespace relay {

int parse_header(const std::uint8_t *data, std::size_t size, Header &out) {
  if (size < 4) {
    return -1;
  }
  out.kind = static_cast<std::uint16_t>(data[0] | (data[1] << 8));
  out.length = static_cast<std::uint16_t>(data[2] | (data[3] << 8));
  if (size < 4u + out.length) {
    return -1;
  }
  std::memcpy(out.name, data + 4, out.length);
  return 4 + out.length;
}

}  // namespace relay
