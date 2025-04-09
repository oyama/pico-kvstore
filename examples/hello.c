#include <stdio.h>
#include "pico/stdlib.h"
#include "kvstore.h"

int main(void) {
    char ssid[33] = {0};
    char password[64] = {0};
    int rc;

    stdio_init_all();
    kvs_init();

    rc  = kvs_get_str("SSID", ssid, sizeof(ssid));
    if (rc != KVSTORE_SUCCESS) {
        printf("%s\n", kvs_strerror(rc));
        return 1;
    }
    rc  = kvs_get_str("PASSWORD", password, sizeof(password));
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
