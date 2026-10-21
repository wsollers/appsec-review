#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

namespace relay {

struct Header {
  std::uint16_t kind;
  std::uint16_t length;
  char name[16];
};

struct Session {
  int id;
  std::string peer;
  bool open;
};

struct Frame {
  std::uint32_t width;
  std::uint32_t height;
  std::uint8_t *pixels;
};

int parse_header(const std::uint8_t *data, std::size_t size, Header &out);

Session *open_session(int id, const std::string &peer);
Session *find_session(int id);
void close_session(Session *session);
int end_session(Session *session);
int touch_session(int id);

Frame *make_frame(std::uint32_t width, std::uint32_t height, std::uint8_t fill);
void free_frame(Frame *frame);

void log_message(const char *message);

int probe_host(const std::string &host);

const char *service_token();
std::string service_url();

}  // namespace relay
