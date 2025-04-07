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
