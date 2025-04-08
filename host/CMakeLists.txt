cmake_minimum_required(VERSION 3.13...3.27)
set(PICO_PLATFORM host)
include(../vendor/pico_sdk_import.cmake)
include(FetchContent)

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)
project(kvstore-util C CXX ASM)
pico_sdk_init()

# The host program also uses the pico-kvstore implementation
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
  kvstore_securekvs
  mbedcrypto
)

# Import mbedtls from pico-sdk into the project directory.
FetchContent_Declare(mbedtls SOURCE_DIR ${PICO_SDK_PATH}/lib/mbedtls EXCLUDE_FROM_ALL)
FetchContent_MakeAvailable(mbedtls)

# The following libraries are not supported in the pico-sdk host environment.
# This implementation uses an alternate implementation.
add_library(pico_rand INTERFACE)
add_library(pico_mbedtls_crypto INTERFACE)
add_library(pico_mbedtls_headers INTERFACE)
add_library(pico_unique_id INTERFACE)
