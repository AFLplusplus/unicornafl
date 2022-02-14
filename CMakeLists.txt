cmake_minimum_required(VERSION 3.14)

# Workaround to fix wrong compiler on macos.
if ((APPLE) AND (NOT CMAKE_C_COMPILER))
    set(CMAKE_C_COMPILER "/usr/bin/cc")
endif()

project(unicornafl)

option(AFL_DEBUG "Enable debug output" off)

set (CMAKE_CXX_STANDARD 17)

option(BUILD_SHARED_LIBS "Build shared instead of static library" ON)

if (BUILD_SHARED_LIBS)
    add_library(unicornafl SHARED unicornafl.cpp)
else()
    add_library(unicornafl STATIC unicornafl.cpp)
    target_compile_options(unicornafl PUBLIC -DUNICORN_BUILD_SHARED=no)
endif()

if (UCAFL_NO_LOG)
    message("Logging is disabled for unicornafl!")
    target_compile_options(unicornafl PUBLIC -DUCAFL_NO_LOG)
endif()

find_package(PkgConfig)
if (PKG_CONFIG_FOUND)
    pkg_check_modules(UNICORN unicorn>=2.0.0)
    if (UNICORN_FOUND)
        target_link_libraries(unicornafl PUBLIC ${UNICORN_LIBRARIES})
        target_include_directories(unicornafl PUBLIC ${UNICORN_INCLUDE_DIRS})
        target_link_directories(unicornafl PUBLIC ${UNICORN_LIBRARY_DIRS})
    else()
        add_subdirectory(unicorn)
        target_link_libraries(unicornafl PUBLIC unicorn)
    endif()
else()
    add_subdirectory(unicorn)
    target_link_libraries(unicornafl PUBLIC unicorn)
endif()

target_link_libraries(unicornafl PUBLIC unicorn)
target_include_directories(unicornafl PUBLIC unicorn/include)
target_include_directories(unicornafl PUBLIC include)
target_include_directories(unicornafl PUBLIC include/unicornafl)
target_include_directories(unicornafl PUBLIC unicorn/build)