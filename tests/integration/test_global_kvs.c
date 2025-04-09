#include <assert.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include "pico/stdlib.h"
#include "pico/btstack_flash_bank.h"
#include "blockdevice/flash.h"
#include "kvstore.h"
#include "kvstore_logkvs.h"
#include "kvstore_securekvs.h"

#define COLOR_GREEN(format) ("\e[32m" format "\e[0m")
#define KVSTORE_BANK_DEFAULT_SIZE  (128 * 1024)
#define KVSTORE_BANK_OFFSET        (PICO_FLASH_BANK_STORAGE_OFFSET - KVSTORE_BANK_DEFAULT_SIZE)


static const char *key1 = "key1";
static const char *key1_value1 = "value1";
static const char *key2 = "name_of_key2";
static const char *key2_value1 = "value3";
static const char *key2_value2 = "value2 of key 2";
static const char *key2_value3 = "Val1 value of key 2            ";
static const char *key3 = "This_is_the_name_of_key3";
static const char *key3_value1 = "Data value of key 3 is the following";

static void test_printf(const char *format, ...) {
    va_list args;
    va_start(args, format);
    int n = vprintf(format, args);
    va_end(args);

    printf(" ");
    for (size_t i = 0; i < 50 - (size_t)n; i++) printf(".");
}

static blockdevice_t *device;

static void setup(void) {
    device = blockdevice_flash_create(KVSTORE_BANK_OFFSET, KVSTORE_BANK_DEFAULT_SIZE);

    size_t length = device->size(device);
    device->erase(device, 0, length);

    kvs_t *kvs = kvs_logkvs_create(device);
    kvs_assign(kvs);
}

static void cleanup(void) {
    kvs_t *kvs = kvs_global_instance();

    size_t length = device->size(device);
    device->erase(device, 0, length);

    free(kvs);
}

void test_global_kvs(void) {
    printf("Global KVS:\n");

    setup();

    test_printf("set");
    int result;
    result = kvs_set(key1, key1_value1, strlen(key1_value1), 0);
    assert(result == KVSTORE_SUCCESS);

    result = kvs_set(key2, key2_value1, strlen(key2_value1), 0);
    assert(result == KVSTORE_SUCCESS);
    result = kvs_set(key2, key2_value2, strlen(key2_value2), 0);
    assert(result == KVSTORE_SUCCESS);
    result = kvs_set(key2, key2_value3, strlen(key2_value3), 0);
    assert(result == KVSTORE_SUCCESS);

    result = kvs_set(key3, key3_value1, strlen(key3_value1), 0);
    assert(result == KVSTORE_SUCCESS);
    printf(COLOR_GREEN("ok\n"));

    test_printf("get");
    char value[256] = {0};
    size_t value_size = 0;
    result = kvs_get(key3, value, sizeof(value), &value_size);
    assert(result == KVSTORE_SUCCESS);
    assert(strlen(key3_value1) == value_size);
    assert(memcmp(key3_value1, value, value_size) == 0);
    printf(COLOR_GREEN("ok\n"));

    test_printf("get_str");
    value_size = 0;
    result = kvs_get_str(key3, value, sizeof(value));
    assert(result == KVSTORE_SUCCESS);
    assert(strcmp(key3_value1, value) == 0);
    printf(COLOR_GREEN("ok\n"));

    test_printf("delete");
    result = kvs_delete(key3);
    assert(result == KVSTORE_SUCCESS);

    result = kvs_get(key3, value, sizeof(value), &value_size);
    assert(result == KVSTORE_ERROR_ITEM_NOT_FOUND);
    printf(COLOR_GREEN("ok\n"));

    cleanup();
}

static void setup_secure(void) {
    kvs_t *underlying_kvs = kvs_logkvs_create(device);
    kvs_t *kvs = kvs_securekvs_create(underlying_kvs, NULL);
    kvs_assign(kvs);
}

void test_global_kvs_secure(void) {
    printf("Global Secure KVS:\n");

    setup_secure();

    test_printf("set");
    int result;
    result = kvs_set(key1, key1_value1, strlen(key1_value1), KVSTORE_REQUIRE_CONFIDENTIALITY_FLAG);
    assert(result == KVSTORE_SUCCESS);

    result = kvs_set(key2, key2_value1, strlen(key2_value1), KVSTORE_REQUIRE_CONFIDENTIALITY_FLAG);
    assert(result == KVSTORE_SUCCESS);
    result = kvs_set(key2, key2_value2, strlen(key2_value2), KVSTORE_REQUIRE_CONFIDENTIALITY_FLAG);
    assert(result == KVSTORE_SUCCESS);
    result = kvs_set(key2, key2_value3, strlen(key2_value3), KVSTORE_REQUIRE_CONFIDENTIALITY_FLAG);
    assert(result == KVSTORE_SUCCESS);

    result = kvs_set(key3, key3_value1, strlen(key3_value1), KVSTORE_REQUIRE_CONFIDENTIALITY_FLAG);
    assert(result == KVSTORE_SUCCESS);
    printf(COLOR_GREEN("ok\n"));

    test_printf("get");
    char value[256] = {0};
    size_t value_size = 0;
    result = kvs_get(key3, value, sizeof(value), &value_size);
    assert(result == KVSTORE_SUCCESS);
    assert(strlen(key3_value1) == value_size);
    assert(memcmp(key3_value1, value, value_size) == 0);
    printf(COLOR_GREEN("ok\n"));

    test_printf("get_str");
    result = kvs_get_str(key3, value, sizeof(value));
    assert(result == KVSTORE_SUCCESS);
    assert(strcmp(key3_value1, value) == 0);
    printf(COLOR_GREEN("ok\n"));


    test_printf("delete");
    result = kvs_delete(key3);
    assert(result == KVSTORE_SUCCESS);

    result = kvs_get(key3, value, sizeof(value), &value_size);
    assert(result == KVSTORE_ERROR_ITEM_NOT_FOUND);
    printf(COLOR_GREEN("ok\n"));

    cleanup();
}
