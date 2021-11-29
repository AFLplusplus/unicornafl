#!/bin/bash

find . -maxdepth 1 "(" -name "*.cpp" -or -name "*.h" ")" -exec clang-format -i -style=file "{}" ";"
find ./include -maxdepth 1 "(" -name "*.cpp" -or -name "*.h" ")" -exec clang-format -i -style=file "{}" ";"