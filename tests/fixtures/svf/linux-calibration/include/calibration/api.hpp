#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

namespace calibration {

int* open_slot();
void close_slot(int* value);
int read_slot(const int* value);

std::string_view text_view();
std::vector<int>::const_iterator position_view();
std::shared_ptr<int> related_owner(const std::shared_ptr<int>& owner);
std::shared_ptr<int> unrelated_owner(const std::shared_ptr<int>& owner);

int array_shape();
int scaled_shape(std::uint16_t count);
int placement_shape(bool shifted);
int duration_shape(bool retained);
int template_shape(std::size_t index);
int indirect_shape(std::size_t index);
int profile_alpha(int value);
int profile_beta(int value);

int coordination_shape(int mode);

}

extern "C" int platform_shape(int mode);
