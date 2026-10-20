// Fixture for the banned-function rules: nothing here may be reported.
#include <cstdio>
#include <cstring>

struct Widget {
  const char *gets() const;
  void strcpy(const char *);
  int strlen() const;
};

void unrelated_names(Widget &widget, char *dst, std::size_t size) {
  widget.strcpy("x");                    // a member function that happens to share a name
  const char *line = widget.gets();
  int count = widget.strlen();
  std::strtoul("1", nullptr, 10);        // not on any list
  strcpy_s(dst, size, "z");              // the bounded replacement is a different name
  my_strcpy(dst, "w");                   // a different identifier
  // strcpy(dst, src) written in a comment
  const char *text = "call strcpy(dst, src) and gets(buf)";  // written in a string
  (void)line;
  (void)count;
  (void)text;
}
