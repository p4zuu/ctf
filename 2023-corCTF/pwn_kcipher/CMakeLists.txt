cmake_minimum_required(VERSION 3.25)
project(kcipher C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_FIND_LIBRARY_SUFFIXES ".a")
set(BUILD_SHARED_LIBS OFF)
set(CMAKE_EXE_LINKER_FLAGS "-static")

add_executable(kcipher
        solve.c)
