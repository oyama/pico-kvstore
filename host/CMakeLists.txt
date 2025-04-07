cmake_minimum_required(VERSION 3.13...3.27)
set(PICO_PLATFORM host)
include(../vendor/pico_sdk_import.cmake)

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)
project(kvstore-util C CXX ASM)
pico_sdk_init()

add_subdirectory(../ ${CMAKE_BINARY_DIR}/pico-kvstore)

add_executable(kvstore-util
  main.c
  blockdevice_file.c
)
target_compile_options(pico_stdlib INTERFACE -w)
target_include_directories(kvstore-util PRIVATE ${CMAKE_CURRENT_LIST_DIR}/include)
target_link_libraries(kvstore-util PRIVATE
  pico_stdlib
  blockdevice
  kvstore
  kvstore_logkvs
)
