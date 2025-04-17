add_executable(demo demo.c)
target_link_libraries(demo PRIVATE
  pico_stdlib
)
pico_add_extra_outputs(demo)


add_executable(hello hello.c)
target_link_libraries(hello PRIVATE
  pico_stdlib
  kvstore
  kvstore_default
)
pico_enable_stdio_usb(hello 1)
pico_add_extra_outputs(hello)

add_executable(secure_hello
  hello.c
  secure_kvs_init.c
)
target_link_libraries(secure_hello PRIVATE
  pico_stdlib
  kvstore
  blockdevice_flash
  kvstore_logkvs
  kvstore_securekvs
  pico_btstack_flash_bank_headers
)
pico_enable_stdio_usb(secure_hello 1)
pico_add_extra_outputs(secure_hello)

add_executable(secure_hello_otp
  hello.c
  secure_kvs_init_otp.c
)
target_link_libraries(secure_hello_otp PRIVATE
  pico_stdlib
  kvstore
  blockdevice_flash
  kvstore_logkvs
  kvstore_securekvs
  pico_btstack_flash_bank_headers
)
pico_enable_stdio_usb(secure_hello_otp 1)
pico_add_extra_outputs(secure_hello_otp)

add_executable(benchmark benchmark.c)
target_compile_options(benchmark PRIVATE -O2)
target_link_libraries(benchmark PRIVATE
  pico_stdlib
  blockdevice_flash
  kvstore
  kvstore_logkvs
  kvstore_securekvs
  pico_btstack_flash_bank_headers
)
pico_enable_stdio_usb(benchmark 1)
pico_add_extra_outputs(benchmark)
