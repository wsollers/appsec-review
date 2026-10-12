// Synthetic code-graph export fixture source. Hand-authored; see ../provenance.json.
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <sys/socket.h>

#define CHECK_LEN(n) ((n) < 64)

struct Handler {
  virtual ~Handler() {}
  virtual void handle(char *dst, const char *src) = 0;
};

struct CopyHandler : Handler {
  void handle(char *dst, const char *src) override { strcpy(dst, src); }
};

struct LogHandler : Handler {
  void handle(char *dst, const char *src) override { printf("%s\n", src); }
};

typedef void (*callback_t)(const char *);

void dispatch(Handler *h, char *dst, const char *src) {
  h->handle(dst, src);
}

void run_callback(callback_t cb, const char *text) {
  cb(text);
}

void copy_checked(char *dst, const char *src, int len) {
  if (len < 64) {
    memcpy(dst, src, len);
  }
  if (CHECK_LEN(len)) {
    dst[len] = 0;
  }
}

void copy_unchecked(char *dst, const char *src, int len) {
  if (len > 0) {
    dst[0] = 1;
  }
  memcpy(dst, src, len);
}

void forward(int sock, const char *src) {
  send(sock, src, strlen(src), 0);
}

int main(int argc, char **argv) {
  char buf[64];
  int n = atoi(argv[1]);
  int m = atoi(getenv("INPUT_LEN"));
  copy_checked(buf, argv[1], n);
  copy_unchecked(buf, argv[1], n);
  copy_unchecked(buf, argv[1], m);
  Handler *h = new CopyHandler();
  dispatch(h, buf, argv[1]);
  forward(3, buf);
  delete h;
  return 0;
}
