cmake_minimum_required(VERSION 3.16)
project(server C)

option(SERVER_BUILD_EXAMPLES "Build the example programs" OFF)

add_subdirectory(third_party/tinylib)

add_executable(server_main src/main.c)
target_link_libraries(server_main PRIVATE tinylib)

if(SERVER_BUILD_EXAMPLES)
  add_subdirectory(examples/hello)
endif()
