# Example of pico-kvstore library

| App                            | Description                                              |
|--------------------------------|----------------------------------------------------------|
| [hello](hello.c)               | Hello Key-Value Store world.                             |
| [secure\_hello](secure_hello.c)| Hello World with Encrypted Key-Value Store.              |
| [benchmark](benchmark.c)       | Benchmark Test.                                          |

## Building sample code

The [pico-sdk](https://github.com/raspberrypi/pico-sdk) build environment is required to build the demonstration, see  [Getting started with Raspberry Pi Pico](https://datasheets.raspberrypi.com/pico/getting-started-with-pico.pdf) to prepare the toolchain for your platform.

Firmware can be built from the _CMake_ build directory of _pico-kvstore_.

```bash
mkdir build; cd build/
PICO_SDK_PATH=/path/to/pico-sdk cmake ..
make hello secure_hello benchmark
```
