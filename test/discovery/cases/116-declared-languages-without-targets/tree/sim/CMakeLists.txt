cmake_minimum_required(VERSION 3.20)
project(sim LANGUAGES C CXX CUDA OBJC)
add_library(sim_core STATIC src/core.c)
add_executable(sim src/main.cpp)
target_link_libraries(sim PRIVATE sim_core)
# experimental/ holds a GPU port and a macOS bridge that no target compiles yet
