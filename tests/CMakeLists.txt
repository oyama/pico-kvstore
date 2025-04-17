set(CMAKE_BUILD_TYPE Debug)

add_executable(unittest EXCLUDE_FROM_ALL
  main.c
  utils.c
  test_logkvs.c
  test_securekvs.c
  test_global_kvs.c
  test_fault.c
)
target_link_libraries(unittest PRIVATE
  pico_stdlib
  blockdevice_heap
  blockdevice_fault
  kvstore_logkvs
  kvstore_securekvs
)

add_library(blockdevice_fault INTERFACE)
target_sources(blockdevice_fault INTERFACE lib/blockdevice_fault.c)
target_include_directories(blockdevice_fault INTERFACE lib)
target_link_libraries(blockdevice_fault INTERFACE blockdevice)

# Switch between linking libraries to build for the host and for the device
if(PICO_ON_DEVICE)
  target_link_libraries(unittest PRIVATE blockdevice_flash)
  pico_add_extra_outputs(unittest)
  pico_enable_stdio_usb(unittest 1)
else()
  include(FetchContent)
  # Import mbedtls from pico-sdk into the project directory.
  FetchContent_Declare(mbedtls SOURCE_DIR ${PICO_SDK_PATH}/lib/mbedtls)
  FetchContent_GetProperties(mbedtls)
  if(NOT mbedtls_POPULATED)
    FetchContent_Populate(mbedtls)
    add_subdirectory(${mbedtls_SOURCE_DIR} ${mbedtls_BINARY_DIR} EXCLUDE_FROM_ALL)
  endif()

  target_link_libraries(unittest PRIVATE mbedcrypto)
  add_library(pico_rand INTERFACE)
  add_library(pico_unique_id INTERFACE)
  add_library(pico_mbedtls_crypto INTERFACE)
  add_library(pico_mbedtls_headers INTERFACE)
  target_compile_options(pico_time INTERFACE -Wno-ignored-attributes)
endif()

if (PICO_CYW43_SUPPORTED)
    target_link_libraries(unittest PRIVATE pico_cyw43_arch_none)
endif()
