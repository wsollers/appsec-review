cmake_minimum_required(VERSION 3.20)
project(app C)
# the sibling library used to be part of this build:
#   add_subdirectory(../libs/sibling sibling-build)
# it is built on its own now
add_executable(app_main main.c)
