cmake_minimum_required(VERSION 3.20)
project(server C)
add_custom_target(tinylib ALL
  COMMAND $(MAKE) -C ${CMAKE_SOURCE_DIR}/third_party/tinylib libtiny.a
  COMMENT "builds the vendored tinylib with its own Makefile")
add_executable(server_main src/main.c)
add_dependencies(server_main tinylib)
target_include_directories(server_main PRIVATE third_party/tinylib/include)
target_link_libraries(server_main PRIVATE ${CMAKE_SOURCE_DIR}/third_party/tinylib/libtiny.a)
