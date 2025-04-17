# pico-kvstore

**Lightweight and Secure Key-Value Store for Raspberry Pi Pico**

![unittest workflow](https://github.com/oyama/pico-kvstore/actions/workflows/host-unittest.yml/badge.svg)

`pico-kvstore` is a compact yet powerful storage solution tailored specifically for Raspberry Pi Pico (RP2040) and Pico 2 (RP2350). It provides an intuitive API optimized for embedded systems, along with a reliable log-structured storage mechanism and built-in AES-128-GCM encryption, enabling easy and secure data handling.

---

## Key Features

### 🛠 Minimalist and Intuitive API

- Essential operations only: `get`, `set`, `delete`, and `find`.
- Seamless integration into Pico SDK projects.
- No complicated initialization required, enabling rapid adoption.

### 📚 Log-Structured Storage Engine

- Optimized specifically for onboard flash memory characteristics.
- Ensures efficient writing performance and flash memory wear-leveling.
- Guarantees data integrity even during unexpected power interruptions.

### 🔐 Secure Data Storage (Integrated AES Encryption)

- Supports AES-128-GCM encryption to robustly protect sensitive data.
- Secure key derivation using HKDF from the RP2350 OTP, device-unique IDs, or user-provided keys.
- Encryption keys are securely cleared from memory immediately after use, reducing the risk of exposure.

### 💻 Comprehensive Host Management Tools

- Efficient host-side management tools compatible with macOS and Linux.
- Enables simple backup, restoration, and editing of storage data with smooth integration with `picotool`.

---

## Recommended Use Cases

Ideal for scenarios including:

- Secure storage of network credentials such as Wi-Fi passwords.
- Management of frequently changing device-specific parameters and settings.
- Logging sensor data and device metadata.
- Safe handling of sensitive information such as cryptographic keys and certificates.

---

## Quick Start Example

This guide demonstrates how to embed Wi-Fi credentials into your Raspberry Pi Pico using pico-kvstore. In this example, the firmware retrieves the Wi-Fi SSID and password from the key-value store. Follow these steps:

### 1. Build and Install Firmware

Prepare a firmware that reads Wi-Fi credentials from the key-value store. For example, create a source file with the following code (this example is also available in the [examples](examples/) directory):

```c
#include <stdio.h>
#include "pico/stdlib.h"
#include "kvstore.h"

int main(void) {
    char ssid[33] = {0};
    char password[64] = {0};
    int rc;

    stdio_init_all();
    kvs_init();

    rc = kvs_get_str("SSID", ssid, sizeof(ssid));
    if (rc != KVSTORE_SUCCESS) {
        printf("%s\n", kvs_strerror(rc));
        return 1;
    }
    rc = kvs_get_str("PASSWORD", password, sizeof(password));
    if (rc != KVSTORE_SUCCESS) {
        printf("%s\n", kvs_strerror(rc));
        return 1;
    }

    printf("Wi-Fi credential:\n"
           "SSID=%s\n"
           "PASSWORD=%s\n",
           ssid, password);
    return 0;
}
```

Build the firmware by executing the following commands:
```bash
mkdir build; cd build
PICO_SDK_PATH=/path/to/pico-sdk cmake ..
make hello
```

Flash the resulting `hello.uf2` firmware onto your Pico (by putting it in `BOOTSEL` mode). At this point, the Pico will attempt to read the _SSID_ and _PASSWORD_ from the key-value store but will output an error message such as:
```
item not found
```
This is expected since the key-value store has not yet been populated.


### 2. Create a Key Value Store Image Using the Host Tool

Next, switch to the host tools to create the storage image that the Pico firmware will access. The host tools are provided in the [host](host/) directory. Build the host tool `kvstore-util` as follows:

```bash
cd ../host
mkdir build; cd build
PICO_SDK_PATH=/path/to/pico-sdk cmake ..
make
```
Now create a key-value store image file `setting.bin` and populate it with the Wi-Fi credentials:

```bash
./kvstore-util create -f setting.bin
./kvstore-util set -f setting.bin -k SSID -v "Home-Wi-Fi"
./kvstore-util set -f setting.bin -k PASSWORD -v "Secret Password"
```

### 3. Write the Storage Image to Pico

Write the generated storage image `setting.bin` to the Pico’s flash memory using [picotool](https://github.com/raspberrypi/picotool). Use the offset appropriate for your device:

- For a Pico with 2MB flash:

```bash
picotool load -o 0x101de000 setting.bin
```

- For a Pico 2 with 4MB flash:

```bash
picotool load -o 0x103de000 setting.bin
```

### 4. Verify on Pico

After flashing the storage image, reboot your Pico. The firmware will now be able to load the key-value store correctly. You should see the following output on the UART or USB CDC console:
```
Wi-Fi credential:
SSID=Home-Wi-Fi
PASSWORD=Secret Password
```
This confirms that the Pico has successfully retrieved the Wi-Fi credentials from the key-value store image created with the host tools.

---

## Benchmark Performance

Performance comparison between Normal and Secure versions of pico-kvstore (16-byte keys and values, latency based on number of stored records):

<img src="https://github.com/user-attachments/assets/d145d9be-ad97-46f4-bc37-1429c6c5674c" width=800 alt="benchmark result"/>


- **Secure KVS** incurs slight overhead due to AES-128-GCM encryption and integrity checks.
- Latency increases moderately as stored records increase, remaining practical for typical embedded applications.

For detailed benchmark methodology and further analysis, refer to [benchmark.c](examples/benchmark.c).

---

## Security and Encryption

- **Encryption Method:** Authenticated encryption using AES-128-GCM.
- **Key Derivation:** Secure HKDF-based key derivation from device-specific IDs is implemented; an OTP-based configuration is also possible (refer to [example](examples/secure_kvs_init_otp.c)).
- **Memory Safety:** Encryption keys are immediately and securely erased after usage.

---

## Host Management Tools

Included host utilities provide:

- Seamless storage image management through integration with `picotool`.
- Easy viewing, backup, and editing of stored data.

Detailed usage instructions are provided in [host/README.md](host/README.md).

---

## License

`pico-kvstore` is released under the permissive 3-Clause BSD License. See the [LICENSE](LICENSE.md) file for details.

---

## Inspiration and Related Projects

This project is inspired by Mbed OS Storage, adopting its design philosophy and optimizing it specifically for Raspberry Pi Pico targets based on modern C11 standards.
