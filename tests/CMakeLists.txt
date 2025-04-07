set(CMAKE_BUILD_TYPE Debug)

add_executable(unittests
  main.c
  test_kvstore_logkvs.c
  test_kvstore_securekvs.c
)
target_link_libraries(unittests PRIVATE
  pico_stdlib
  blockdevice_heap
  kvstore_logkvs
  kvstore_securekvs
)
pico_add_extra_outputs(unittests)
pico_enable_stdio_usb(unittests 1)

add_subdirectory(integration)
