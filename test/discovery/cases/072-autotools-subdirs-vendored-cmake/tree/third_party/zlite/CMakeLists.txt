cmake_minimum_required(VERSION 3.20)
project(zlite C)
add_library(zlite STATIC zlite.c)
target_include_directories(zlite PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
