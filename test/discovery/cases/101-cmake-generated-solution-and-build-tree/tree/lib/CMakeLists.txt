cmake_minimum_required(VERSION 3.20)
project(lib C)
add_library(lib STATIC src/lib.c)
target_include_directories(lib PUBLIC include)
