cmake_minimum_required(VERSION 3.20)
project(gtest CXX)
add_library(gtest STATIC src/gtest-all.cc)
target_include_directories(gtest PUBLIC include)
