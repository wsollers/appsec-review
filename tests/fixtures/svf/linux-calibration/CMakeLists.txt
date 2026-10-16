cmake_minimum_required(VERSION 3.20)

project(linux_calibration LANGUAGES C CXX)

set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

option(CALIBRATION_ADDRESS_INSTRUMENTATION "Enable address and undefined-behavior instrumentation" OFF)
option(CALIBRATION_THREAD_INSTRUMENTATION "Enable thread instrumentation" OFF)

if(CALIBRATION_ADDRESS_INSTRUMENTATION AND CALIBRATION_THREAD_INSTRUMENTATION)
  message(FATAL_ERROR "Instrumentation modes are mutually exclusive")
endif()

find_package(Threads REQUIRED)

add_library(variant_alpha OBJECT src/profile.cpp)
target_compile_definitions(variant_alpha PRIVATE CALIBRATION_PROFILE=1 CALIBRATION_PROFILE_NAME=profile_alpha)
target_include_directories(variant_alpha PRIVATE include)

add_library(variant_beta OBJECT src/profile.cpp)
target_compile_definitions(variant_beta PRIVATE CALIBRATION_PROFILE=2 CALIBRATION_PROFILE_NAME=profile_beta)
target_include_directories(variant_beta PRIVATE include)

add_library(foundation STATIC
  src/storage.cpp
  src/sequences.cpp
  $<TARGET_OBJECTS:variant_alpha>
  $<TARGET_OBJECTS:variant_beta>
)
target_include_directories(foundation PUBLIC include)

add_library(coordination SHARED
  src/coordination.cpp
  src/platform.c
)
target_include_directories(coordination PUBLIC include)
target_link_libraries(coordination PUBLIC Threads::Threads)

add_executable(observer_a app/observer_a.cpp)
target_link_libraries(observer_a PRIVATE foundation coordination)

add_executable(observer_b app/observer_b.cpp)
target_link_libraries(observer_b PRIVATE coordination foundation)

set(calibration_targets
  variant_alpha
  variant_beta
  foundation
  coordination
  observer_a
  observer_b
)

foreach(target IN LISTS calibration_targets)
  target_compile_options(${target} PRIVATE -Wall -Wextra -Wpedantic -Wconversion)
endforeach()

if(CALIBRATION_ADDRESS_INSTRUMENTATION)
  foreach(target IN LISTS calibration_targets)
    target_compile_options(${target} PRIVATE
      -O1 -g -fno-omit-frame-pointer -fsanitize=address,undefined
      -fsanitize-address-use-after-scope
    )
    target_link_options(${target} PRIVATE -fsanitize=address,undefined)
  endforeach()
endif()

if(CALIBRATION_THREAD_INSTRUMENTATION)
  foreach(target IN LISTS calibration_targets)
    target_compile_options(${target} PRIVATE -O1 -g -fno-omit-frame-pointer -fsanitize=thread)
    target_link_options(${target} PRIVATE -fsanitize=thread)
  endforeach()
endif()
