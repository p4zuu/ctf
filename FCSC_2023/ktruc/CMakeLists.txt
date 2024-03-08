cmake_minimum_required(VERSION 3.27)
project(ktruc C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_EXE_LINKER_FLAGS "-static")
set(CMAKE_C_COMPILER /usr/bin/x86_64-linux-musl-gcc)

add_executable(solve
        solve.c)
