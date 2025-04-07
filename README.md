# pico-kvstore

**Lightweight, Robust, and Secure Key-Value Store for Raspberry Pi Pico**

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

Below is a simple demonstration of using `pico-kvstore`:

```c
#include <stdio.h>
#include <string.h>
#include "pico/stdlib.h"
#include "kvstore.h"

int main(void) {
    stdio_init_all();
    kvs_init();

    const char *password = "Wi-Fi Password";
    kvs_set("PASSWORD", password, strlen(password), 0);

    char buffer[64];
    size_t read_size;
    if (kvs_get("PASSWORD", buffer, sizeof(buffer), &read_size) == 0) {
        printf("Retrieved PASSWORD: %s (%u bytes)\n", buffer, read_size);
    }

    kvs_delete("PASSWORD");

    return 0;
}
```

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
- **Key Derivation:** Secure HKDF-based key derivation from device-specific IDs or OTP.
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
