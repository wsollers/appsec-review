cmake_minimum_required(VERSION 3.20)
project(fmtlite C)
add_library(fmtlite STATIC src/fmtlite.c)
target_include_directories(fmtlite PUBLIC include)
