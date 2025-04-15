set(CMAKE_BUILD_TYPE Debug)

add_executable(unittests
  main.c
  test_kvstore_logkvs.c
  test_kvstore_securekvs.c
  test_fault.c
)
target_link_libraries(unittests PRIVATE
  pico_stdlib
  blockdevice_heap
  blockdevice_fault
  kvstore_logkvs
  kvstore_securekvs
)
pico_add_extra_outputs(unittests)
pico_enable_stdio_usb(unittests 1)


add_library(blockdevice_fault INTERFACE)
target_sources(blockdevice_fault INTERFACE blockdevice_fault.c)
target_link_libraries(blockdevice_fault INTERFACE blockdevice)

add_subdirectory(integration)
