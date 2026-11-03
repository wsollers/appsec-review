#include <algorithm>
#include <vector>

namespace demo {

int global_limit = 4; // ANCHOR:none

class Buffer {
public:
    int total(const std::vector<int> &values) const { // BEGIN:total
        int sum = 0;
        std::for_each(values.begin(), values.end(), [&sum](int value) {
            sum += value; // ANCHOR:total
        });
        return sum; // ANCHOR:total
    } // END:total
};

int Scale(int value) { // BEGIN:Scale
    auto twice = [](int x) { return x * 2; };
    return twice(value); // ANCHOR:Scale
} // END:Scale

}  // namespace demo
