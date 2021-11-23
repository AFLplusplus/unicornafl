cmake_minimum_required(VERSION 3.14)

project(unicorn2afl)

option(AFL_DEBUG "Enable debug output" off)

set (CMAKE_CXX_STANDARD 17)

# TODO: Link a installed global unicorn if possible?
add_subdirectory(unicorn)

add_library(unicorn2afl SHARED unicorn2afl.cpp)

if (AFL_DEBUG)
    target_compile_options(unicorn2afl PRIVATE -DAFL_DEBUG)
endif()

target_link_libraries(unicorn2afl PRIVATE unicorn)
target_include_directories(unicorn2afl PRIVATE include)
target_include_directories(unicorn2afl PRIVATE include/unicorn2afl)
target_include_directories(unicorn2afl PRIVATE unicorn/include)