# Testing Methods

pico-kvstore provides unit testing on the development host and integration testing on the device.

## Unit testing on the development host

Unit tests on the development host build the pico-sdk with `PICO_PLATFORM=host` and build the regular.

```bash
mkdir build
PICO_SDK_PATH=/path/to/pico-sdk cmake .. -DPICO_PLATFORM=host
make unittest
./test/unittest

```

## Integration on target devices

Integration testing on the target device is performed by building and installing firmware.
```bash
mkdir build
PICO_SDK_PATH=/path/to/pico-sdk cmake .. -DPICO_BOARD=pico
make unittest
```

The test firmware is built as `test/unittest.uf2`; install the firmware on a Pico running in BOOTSEL mode. Execution results are verified via UART or USB CDC.

## Note

When switching test targets, the build directory must be deleted and cmake must be run again.
