#include <assert.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include "pico/stdlib.h"
#include "blockdevice/heap.h"
#include "kvstore_logkvs.h"
#include "kvstore_securekvs.h"
#include <ctype.h>

#define COLOR_GREEN(format)  ("\e[32m" format "\e[0m")
#define HEAP_STORAGE_SIZE    (64 * 1024)

static const char *key1        = "key1";
static const char *key1_value1 = "value1";
static const char *key2        = "name_of_key2";
static const char *key2_value1 = "value3";
static const char *key2_value2 = "value2 of key 2";
static const char *key2_value3 = "Val1 value of key 2            ";
static const char *key3        = "This_is_the_name_of_key3";
static const char *key3_value1 = "Data value of key 3 is the following";
static const char *key3_value2 = "Data value of key 3 is super long                                                                                                                                                                                                                                     ";

static void test_printf(const char *format, ...) {
    va_list args;
    va_start(args, format);
    int n = vprintf(format, args);
    va_end(args);

    printf(" ");
    for (size_t i = 0; i < 50 - (size_t)n; i++)
        printf(".");
}

static void setup(blockdevice_t *device) {
    size_t length = device->size(device);
    device->erase(device, 0, length);
}

static void cleanup(blockdevice_t *device) {
    size_t length = device->size(device);
    device->erase(device, 0, length);
}

static void test_basic_crud(kvs_t *kvs) {
    test_printf("set,read,update,delete");

    int result;

    result = kvs->set(kvs, key1, key1_value1, strlen(key1_value1), KVSTORE_REQUIRE_CONFIDENTIALITY_FLAG);
    assert(result == KVSTORE_SUCCESS);

    result = kvs->set(kvs, key2, key2_value1, strlen(key2_value1), KVSTORE_REQUIRE_CONFIDENTIALITY_FLAG);
    assert(result == KVSTORE_SUCCESS);
    result = kvs->set(kvs, key2, key2_value2, strlen(key2_value2), KVSTORE_REQUIRE_CONFIDENTIALITY_FLAG);
    assert(result == KVSTORE_SUCCESS);
    result = kvs->set(kvs, key2, key2_value3, strlen(key2_value3), KVSTORE_REQUIRE_CONFIDENTIALITY_FLAG);
    assert(result == KVSTORE_SUCCESS);

    result = kvs->set(kvs, key3, key3_value1, strlen(key3_value1), KVSTORE_REQUIRE_CONFIDENTIALITY_FLAG);
    assert(result == KVSTORE_SUCCESS);

    char value[256] = {0};
    size_t value_size = 0;
    result = kvs->get(kvs, key3, value, sizeof(value), &value_size, 0);
    assert(result == KVSTORE_SUCCESS);
    assert(strlen(key3_value1) == value_size);
    assert(strcmp(key3_value1, value) == 0);

    result = kvs->set(kvs, key3, key3_value2, strlen(key3_value2), KVSTORE_REQUIRE_CONFIDENTIALITY_FLAG);
    assert(result == KVSTORE_SUCCESS);

    char value2[1024] = {0};
    result = kvs->get(kvs, key3, value2, sizeof(value2), &value_size, 0);
    assert(result == KVSTORE_SUCCESS);
    assert(strlen(key3_value2) == value_size);
    assert(strcmp(key3_value2, value2) == 0);

    result = kvs->delete(kvs, key3);
    assert(result == KVSTORE_SUCCESS);

    result = kvs->get(kvs, key3, value, sizeof(value), &value_size, 0);
    assert(result == KVSTORE_ERROR_ITEM_NOT_FOUND);

    printf(COLOR_GREEN("ok\n"));
}

static void test_various_size_key(kvs_t *kvs) {
    test_printf("1 to 128-byte key");
    int result;
    char key[128] = {0};
    const char *value = "value";
    char buffer[4096];
    for (size_t size = 1; size < 128; size++) {
        for (size_t i = 0; i < size; i++)
            key[i] = 'a' + (i % 26);
        key[size] = '\0';

        result = kvs->set(kvs, key, value, strlen(value), 0);
        assert(result == KVSTORE_SUCCESS);
        result = kvs->get(kvs, key, buffer, sizeof(buffer), NULL, 0);
        assert(result == KVSTORE_SUCCESS);
        assert(strcmp(value, buffer) == 0);
        result = kvs->delete(kvs, key);
        assert(result == KVSTORE_SUCCESS);
    }
    printf(COLOR_GREEN("ok\n"));

    test_printf("over 128-byte key");
    const char *over_size_key = "12345678901234567890123456789012345678901234567890"
                                "12345678901234567890123456789012345678901234567890"
                                "12345678901234567890123456789012345678901234567890"
                                "12345678901234567890123456789012345678901234567890"
                                "12345678901234567890ABCDEFGHI";
    result = kvs->set(kvs, over_size_key, value, strlen(value), 0);
    assert(result == KVSTORE_ERROR_INVALID_ARGUMENT);
    printf(COLOR_GREEN("ok\n"));
}

static void test_various_size_value(kvs_t *kvs) {
    test_printf("1 to 4096 bytes value");
    int result;
    char key[] = "various-value";
    char value[4096];
    char buffer[4096];
    for (size_t size = 1; size < 4096; size++) {
        for (size_t i = 0; i < size; i++)
            value[i] = 'a' + (i % 26);

        result = kvs->set(kvs, key, value, size, 0);
        assert(result == KVSTORE_SUCCESS);
        size_t value_size = 0;
        result = kvs->get(kvs, key, buffer, sizeof(buffer), &value_size, 0);
        assert(result == KVSTORE_SUCCESS);
        assert(value_size == size);
        assert(memcmp(value, buffer, size) == 0);
        result = kvs->delete(kvs, key);
        assert(result == KVSTORE_SUCCESS);
    }
    printf(COLOR_GREEN("ok\n"));
}


void test_kvstore_securekvs(void) {
    printf("Secure Key-Value Store, Heap memory:\n");
    blockdevice_t *heap = blockdevice_heap_create(HEAP_STORAGE_SIZE);
    assert(heap != NULL);
    setup(heap);

    kvs_t *kvs = kvs_logkvs_create(heap);
    assert(kvs != NULL);

    kvs_t *secure_kvs = kvs_securekvs_create(kvs, NULL);

    test_basic_crud(secure_kvs);
    test_various_size_key(kvs);
    test_various_size_value(kvs);

    cleanup(heap);
    kvs_securekvs_free(secure_kvs);
    kvs_logkvs_free(kvs);
    blockdevice_heap_free(heap);
}
