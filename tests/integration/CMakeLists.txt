set(CMAKE_BUILD_TYPE Debug)

add_executable(integration
  main.c
  test_global_kvs.c
)
target_link_libraries(integration PRIVATE
  pico_stdlib
  kvstore
  kvstore_logkvs
  kvstore_securekvs
  blockdevice_flash
  pico_btstack_flash_bank_headers
)
pico_enable_stdio_usb(integration 1)
pico_add_extra_outputs(integration)
