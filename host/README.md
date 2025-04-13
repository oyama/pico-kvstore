# kvstore-util

**kvstore-util** is a command-line utility for managing image files of a log-structured key-value store (LogKVS) designed for use with Raspberry Pi Pico.
It allows creating and manipulating KVS images on the host environment. The resulting image files can be written to devices using `picotool`.

## Build Instructions

```bash
cd host-tool
mkdir build && cd build
PICO_SDK_PATH=/path/to/pico-sdk cmake ..
make
```

> Environment variable `PICO_SDK_PATH` is required. Since this builds for the host, do not specify `PICO_BOARD`.

> Note: Windows will not build correctly, so please run it under WSL (Windows Subsystem for Linux).
## Usage

```
kvstore-util create -f <filename> [-s <size>]
kvstore-util set -f <filename> -k <key> -v <value> [-e <encrypt-key>]
kvstore-util get -f <filename> -k <key> [-e <encrypt-key>]
kvstore-util delete -f <filename> -k <key>
kvstore-util find -f <filename> [-k <prefix>]
```

## Command Descriptions

| Command    | Description                                                                 |
|------------|-----------------------------------------------------------------------------|
| `create`   | Creates a new KVS image file with the specified size (default: 128KB)       |
| `set`      | Stores a value under the specified key                                      |
| `get`      | Retrieves the value for a specified key (or lists all if `-k` is omitted)   |
| `delete`   | Deletes the specified key                                                   |
| `find`     | Lists keys, optionally filtering by prefix (`-k`)                           |

### Options

| Option               | Description                                                                          |
|----------------------|--------------------------------------------------------------------------------------|
| `-f <filename>`      | Path to the KVS image file (required)                                                |
| `-k <key>`           | Key to operate on (used with `get`, `set`, `delete`, `find`)                         |
| `-v <value>`         | Value to store (required for `set`)                                                  |
| `-s <size>`          | Image size in bytes (used only with `create`, default: `128KB`)                      |
| `-e <encrypt-key>`   | The encryption key to be used for storage, specified as a 128-bit hex (32 characters)|

## Examples

```bash
# Create an image file (128KB)
kvstore-util create -f kvstore.bin

# Store a key-value pair
kvstore-util set -f kvstore.bin -k foo -v bar

# Retrieve a value
kvstore-util get -f kvstore.bin -k foo

# Delete a key
kvstore-util delete -f kvstore.bin -k foo

# List all keys
kvstore-util find -f kvstore.bin
```

## Writing to the Device (Example)

You can use `picotool` to write the KVS image to the flash memory of your Raspberry Pi Pico:

```bash
picotool load -o 0x101de000 kvstore.bin
```

> `0x101de000` is the default location used by `kvs_init()`. Adjust as needed for your setup.


## License

BSD 3-Clause License
