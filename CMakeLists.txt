cmake_minimum_required(VERSION 3.13...3.27)
include(vendor/pico_sdk_import.cmake)
add_subdirectory(lib/pico-vfs)

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)
project(pico-kvstore C CXX ASM)
pico_sdk_init()

# Key-Value Store Global API Library
add_library(kvstore INTERFACE)
target_sources(kvstore INTERFACE src/kvstore.c)
target_include_directories(kvstore INTERFACE ${CMAKE_CURRENT_LIST_DIR}/include)

# Log structured key-value store implementation
add_library(kvstore_logkvs INTERFACE)
target_sources(kvstore_logkvs INTERFACE
    src/kvstore_logkvs.c
    src/blockdevice_stage.c
    src/crc32_ansi.c
)
target_include_directories(kvstore_logkvs INTERFACE ${CMAKE_CURRENT_LIST_DIR}/include)
target_link_libraries(kvstore_logkvs INTERFACE
    kvstore
    blockdevice
)

# Secure store implementation
add_library(kvstore_securekvs INTERFACE)
target_sources(kvstore_securekvs INTERFACE
    src/kvstore_securekvs.c
)
target_include_directories(kvstore_securekvs INTERFACE ${CMAKE_CURRENT_LIST_DIR}/include)
target_link_libraries(kvstore_securekvs INTERFACE
    kvstore
    blockdevice
    pico_mbedtls_crypto
    pico_mbedtls_headers
    pico_rand
    pico_unique_id
)

# Default setup for general-purpose users
add_library(kvstore_default INTERFACE)
target_sources(kvstore_default INTERFACE src/kvs_init.c)
target_include_directories(kvstore_default INTERFACE ${CMAKE_CURRENT_LIST_DIR}/include)
target_link_libraries(kvstore_default INTERFACE
    kvstore
    kvstore_logkvs
    blockdevice_flash
    pico_btstack_flash_bank_headers
)

# NOTE: Additional targets are only included in the build of the pico-kvstore project root
if("${CMAKE_CURRENT_LIST_DIR}" STREQUAL "${CMAKE_SOURCE_DIR}")
    if(PICO_ON_DEVICE)
      add_subdirectory(examples EXCLUDE_FROM_ALL)
    endif()
    add_subdirectory(tests EXCLUDE_FROM_ALL)
endif()
