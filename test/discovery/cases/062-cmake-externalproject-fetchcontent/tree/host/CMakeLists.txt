cmake_minimum_required(VERSION 3.24)
project(host C)
include(ExternalProject)
include(FetchContent)
ExternalProject_Add(tinylib
  SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/external/tinylib
  INSTALL_COMMAND "")
FetchContent_Declare(fmtlite SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/external/fmtlite)
FetchContent_MakeAvailable(fmtlite)
add_executable(host_main src/main.c)
add_dependencies(host_main tinylib)
target_link_libraries(host_main PRIVATE fmtlite)
