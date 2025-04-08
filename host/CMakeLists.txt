cmake_minimum_required(VERSION 3.13...3.27)
set(PICO_PLATFORM host)
include(../vendor/pico_sdk_import.cmake)

include(FetchContent)

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)
project(kvstore-util C CXX ASM)
pico_sdk_init()


add_subdirectory(../ ${CMAKE_BINARY_DIR}/pico-kvstore)

FetchContent_Declare(mbedtls SOURCE_DIR ${PICO_SDK_PATH}/lib/mbedtls EXCLUDE_FROM_ALL)
FetchContent_MakeAvailable(mbedtls)

add_executable(kvstore-util
  main.c
  blockdevice_file.c
)

add_library(pico_rand INTERFACE)
add_library(pico_mbedtls_crypto INTERFACE)
add_library(pico_mbedtls_headers INTERFACE)
add_library(pico_unique_id INTERFACE)

target_compile_options(pico_stdlib INTERFACE -w)
target_include_directories(kvstore-util PRIVATE ${CMAKE_CURRENT_LIST_DIR}/include)
target_link_libraries(kvstore-util PRIVATE
  pico_stdlib
  blockdevice
  kvstore
  kvstore_logkvs
  kvstore_securekvs
  mbedcrypto
)
