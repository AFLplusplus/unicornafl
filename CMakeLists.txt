cmake_minimum_required(VERSION 3.14)

project(unicornafl)

option(AFL_DEBUG "Enable debug output" off)

set (CMAKE_CXX_STANDARD 17)

# TODO: Link a installed global unicorn if possible?
add_subdirectory(unicorn)

add_library(unicorn2afl STATIC unicornafl.cpp)

if (AFL_DEBUG)
    target_compile_options(unicornafl PRIVATE -DAFL_DEBUG)
endif()

find_package(PkgConfig)
if (PKG_CONFIG_FOUND)
    pkg_check_modules(UNICORN unicorn>=2.0.0)
    if (UNICORN_FOUND)
        target_link_libraries(unicornafl PRIVATE ${UNICORN_LIBRARIES})
        target_include_directories(unicornafl PRIVATE ${UNICORN_INCLUDE_DIRS})
        target_link_directories(unicornafl PRIVATE ${UNICORN_LIBRARY_DIRS})
    else()
        add_subdirectory(unicorn)
        target_link_libraries(unicornafl PRIVATE unicorn)
    endif()
else()
    add_subdirectory(unicorn)
    target_link_libraries(unicornafl PRIVATE unicorn)
endif()

target_link_libraries(unicornafl PRIVATE unicorn)
target_include_directories(unicornafl PRIVATE include)
target_include_directories(unicornafl PRIVATE include/unicornafl)
target_include_directories(unicornafl PRIVATE unicorn/include)
