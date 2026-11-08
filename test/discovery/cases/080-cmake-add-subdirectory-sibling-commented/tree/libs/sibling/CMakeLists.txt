cmake_minimum_required(VERSION 3.20)
project(sibling C)
add_library(sibling STATIC sibling.c)
target_include_directories(sibling PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
