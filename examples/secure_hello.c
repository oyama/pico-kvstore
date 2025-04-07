#include <stdio.h>
#include <string.h>
#include "pico/stdlib.h"
#include "kvstore.h"

int main(void) {
    stdio_init_all();
    kvs_init();

    char value[1024] = {0};
    size_t value_len = 0;
    int rc = kvs_get("MESSAGE", value, sizeof(value), &value_len);
    if (rc == KVSTORE_SUCCESS) {
        printf("MESSAGE=\"%s\" (%u bytes)\n", value, value_len);
    } else if (rc == KVSTORE_ERROR_ITEM_NOT_FOUND) {
        printf("MESSAGE not found. create MESSAGE\n");
        const char *message = "Hello World!";
        rc = kvs_set("MESSAGE", message, strlen(message), KVSTORE_REQUIRE_CONFIDENTIALITY_FLAG);
        if (rc != KVSTORE_SUCCESS) {
            fprintf(stderr, "kvs_set fail rc=%d\n", rc);
        }
    } else {
        fprintf(stderr, "kvs_get fail rc=%d\n", rc);
    }

    while (true) {
        tight_loop_contents();
    }
    return 0;
}
