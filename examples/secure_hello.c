#include <stdio.h>
#include <string.h>
#include "pico/stdlib.h"
#include "kvstore.h"

int main(void) {
    stdio_init_all();
    kvs_init();

    char value[1024] = {0};
    int rc = kvs_get_str("MESSAGE", value, sizeof(value));
    if (rc == KVSTORE_SUCCESS) {
        printf("MESSAGE=\"%s\"\n", value);
    } else if (rc == KVSTORE_ERROR_ITEM_NOT_FOUND) {
        printf("MESSAGE not found. create MESSAGE\n");
        const char message[] = "Hello World!";
        rc = kvs_set("MESSAGE", message, strlen(message), KVSTORE_REQUIRE_CONFIDENTIALITY_FLAG);
        if (rc != KVSTORE_SUCCESS) {
            fprintf(stderr, "kvs_set: %s\n", kvs_strerror(rc));
        }
    } else {
        fprintf(stderr, "kvs_get: %s\n", kvs_strerror(rc));
    }

    while (true) {
        tight_loop_contents();
    }
    return 0;
}
