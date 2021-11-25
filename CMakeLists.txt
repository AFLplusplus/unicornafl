cmake_minimum_required(VERSION 3.14)

project(unicorn2afl)

option(AFL_DEBUG "Enable debug output" off)

set (CMAKE_CXX_STANDARD 17)

add_library(unicorn2afl SHARED unicorn2afl.cpp)

if (AFL_DEBUG)
    target_compile_options(unicorn2afl PRIVATE -DAFL_DEBUG)
endif()

find_package(PkgConfig)
if (PKG_CONFIG_FOUND)
    pkg_check_modules(UNICORN unicorn>=2.0.0)
    if (UNICORN_FOUND)
        target_link_libraries(unicorn2afl PRIVATE ${UNICORN_LIBRARIES})
        target_include_directories(unicorn2afl PRIVATE ${UNICORN_INCLUDE_DIRS})
        target_link_directories(unicorn2afl PRIVATE ${UNICORN_LIBRARY_DIRS})
    endif()
else()
    add_subdirectory(unicorn)
    target_link_libraries(unicorn2afl PRIVATE unicorn)
endif()

target_include_directories(unicorn2afl PRIVATE include)
target_include_directories(unicorn2afl PRIVATE include/unicorn2afl)