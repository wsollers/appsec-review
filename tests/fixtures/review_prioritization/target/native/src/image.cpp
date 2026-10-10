#include <libxml/parser.h>
#include <iostream>
#include <stdexcept>
#include <vector>
#include "codec.h"

#pragma GCC diagnostic ignored "-Wsign-compare"

namespace media {

class Loader {
public:
    xmlDocPtr parse_manifest(const char *data, int size) {
        return xmlReadMemory(data, size, "manifest.xml", nullptr, XML_PARSE_NOENT);
    }

    int count_large(const std::vector<int> &values, int limit) {
        auto above = [limit](int value) {
            return value > limit || value < -limit;
        };
        int total = 0;
        try {
            for (int value : values) {
                if (above(value)) {
                    total++;
                }
            }
        } catch (const std::exception &error) {
            return -1;
        }
        return total;
    }

    void log_value(int value) {
        std::cout << "value " << value << " flags " << (value | 0) << std::endl;
    }
};

}  // namespace media
