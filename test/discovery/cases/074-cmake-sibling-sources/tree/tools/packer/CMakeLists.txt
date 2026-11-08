cmake_minimum_required(VERSION 3.20)
project(packer C)
# the retired codec lived in ../../common/src/other.c; it is not part of this target
add_executable(packer main.c ../../common/src/util.c)
target_include_directories(packer PRIVATE ../../common/include)
