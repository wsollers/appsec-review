// Fixture for the banned-function rules: each line that ends in a tier marker must be reported at
// that tier.
#include <cstdio>
#include <cstdlib>
#include <cstring>

void high_tier(char *dst, const char *src, char *buf, int count) {
  std::strcpy(dst, src);  // EXPECT high
  strcat(dst, src);  // EXPECT high
  sprintf(buf, "%s", src);  // EXPECT high
  gets(buf);  // EXPECT high
  sscanf(src, "%s", buf);  // EXPECT high
  _itoa(count, buf, 10);  // EXPECT high
}

void warning_tier(char *dst, const char *src, std::size_t count) {
  std::strncpy(dst, src, count);  // EXPECT warning
  char *scratch = static_cast<char *>(alloca(32));  // EXPECT warning
  std::size_t length = strlen(src);  // EXPECT warning
  char *token = strtok(dst, ",");  // EXPECT warning
  (void)scratch;
  (void)length;
  (void)token;
}

void review_tier(char *dst, const char *src, std::size_t count) {
  void *block = malloc(count);  // EXPECT review
  std::memcpy(dst, src, count);  // EXPECT review
  int same = strcmp(dst, src);  // EXPECT review
  printf("%s", src);  // EXPECT review
  (void)block;
  (void)same;
}
