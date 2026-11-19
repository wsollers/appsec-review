#include <cassert>
#include <cstddef>

struct Counter
{
    std::size_t value;
    explicit Counter(std::size_t initial) : value(initial) {}
    void increment() { ++value; }
};

int main()
{
    Counter counter(2);
    counter.increment();
    assert(counter.value == 3);
}
