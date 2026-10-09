#include <iostream>
extern "C" int fixture_answer(void);
int main() {
  std::cout << fixture_answer() << '\n';
  return 0;
}
