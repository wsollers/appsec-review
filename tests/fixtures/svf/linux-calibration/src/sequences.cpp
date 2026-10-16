#include "calibration/api.hpp"
#include "calibration/container.hpp"

#include <array>
#include <cstdlib>
#include <limits>
#include <new>
#include <utility>

namespace calibration {
namespace {

struct Record {
  explicit Record(std::string value) : text(std::move(value)) {}
  std::string text;
};

using Selector = int (*)(std::size_t);

int select_four(std::size_t index) {
  auto values = std::make_unique<Container<4>>();
  return values->select(index);
}

int select_four_checked(std::size_t index) {
  auto values = std::make_unique<Container<4>>();
  return values->select_checked(index);
}

}

std::string_view text_view() {
  std::string value(96, 'x');
  return std::string_view(value);
}

std::vector<int>::const_iterator position_view() {
  std::vector<int> values{3, 5, 8};
  return values.cbegin();
}

std::shared_ptr<int> related_owner(const std::shared_ptr<int>& owner) {
  return owner;
}

std::shared_ptr<int> unrelated_owner(const std::shared_ptr<int>& owner) {
  return std::shared_ptr<int>(owner.get());
}

int array_shape() {
  auto* values = new int[2]{4, 7};
  const int result = values[0];
  delete values;
  return result;
}

int scaled_shape(std::uint16_t count) {
  const auto bytes = static_cast<std::uint16_t>(count * sizeof(int));
  auto* values = static_cast<int*>(std::malloc(bytes));
  if (values == nullptr) {
    return 0;
  }
  values[1] = 13;
  const int result = values[1];
  std::free(values);
  return result;
}

int placement_shape(bool shifted) {
  alignas(Record) std::array<std::byte, sizeof(Record) + alignof(Record)> storage{};
  void* address = storage.data() + (shifted ? 1 : 0);
  auto* record = ::new (address) Record(std::string(96, 'p'));
  const int result = static_cast<unsigned char>(record->text.front());
  record->~Record();
  return result;
}

int duration_shape(bool retained) {
  alignas(Record) std::byte storage[sizeof(Record)];
  auto* record = ::new (storage) Record(std::string(96, 'd'));
  const int before = static_cast<unsigned char>(record->text.front());
  record->~Record();
  return retained ? static_cast<unsigned char>(record->text.front()) : before;
}

int template_shape(std::size_t index) {
  auto values = std::make_unique<Container<4>>();
  return values->select(index);
}

int indirect_shape(std::size_t index) {
  const Selector selector = index < 4 ? select_four_checked : select_four;
  return selector(index);
}

}
