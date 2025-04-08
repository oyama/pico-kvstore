# Example of pico-kvstore library

| App                            | Description                                              |
|--------------------------------|----------------------------------------------------------|
| [hello](hello.c)               | Hello Key-Value Store world.                             |
| [secure\_hello](secure_hello.c)| Hello World with Encrypted Key-Value Store.              |
| [secure\_kvs\_init](secure_kvs_init.c) | Sample initialization function `kvs_init()` that derives and encrypts a secret key based on device ID.|
| [secure\_kvs\_init\_otp](secure_kvs_init_otp.c) | Sample initialization function `kvs_init()` that derives and encrypts the secret key based on the OTP.|
| [benchmark](benchmark.c)       | Benchmark Test.                                          |

## Building sample code

The [pico-sdk](https://github.com/raspberrypi/pico-sdk) build environment is required to build the demonstration, see  [Getting started with Raspberry Pi Pico](https://datasheets.raspberrypi.com/pico/getting-started-with-pico.pdf) to prepare the toolchain for your platform.

Firmware can be built from the _CMake_ build directory of _pico-kvstore_.

```bash
mkdir build; cd build/
PICO_SDK_PATH=/path/to/pico-sdk cmake ..
make hello secure_hello benchmark
```
