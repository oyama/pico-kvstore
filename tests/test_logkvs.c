#include <assert.h>
#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include "kvstore_logkvs.h"
#include "pico/stdlib.h"
#include "utils.h"

static const char *key1        = "key1";
static const char *key1_value1 = "value1";
static const char *key2        = "name_of_key2";
static const char *key2_value1 = "value3";
static const char *key2_value2 = "value2 of key 2";
static const char *key2_value3 = "Val1 value of key 2            ";
static const char *key3        = "This_is_the_name_of_key3";
static const char *key3_value1 = "Data value of key 3 is the following";

static void setup(blockdevice_t *device) {
    size_t length = device->size(device);
    device->erase(device, 0, length);
}

static void cleanup(blockdevice_t *device) {
    size_t length = device->size(device);
    device->erase(device, 0, length);
}

static void test_basic_crud(kvs_t *kvs) {
    int result;
    char value[256] = {0};
    size_t value_size = 0;

    test_printf("create");
    result = kvs->set(kvs, key1, key1_value1, strlen(key1_value1), 0);
    assert(result == KVSTORE_SUCCESS);
    printf(COLOR_GREEN("ok\n"));

    test_printf("read");
    result = kvs->get(kvs, key1, value, sizeof(value), &value_size, 0);
    assert(result == KVSTORE_SUCCESS);
    assert(strlen(key1_value1) == value_size);
    assert(memcmp(key1_value1, value, value_size) == 0);
    printf(COLOR_GREEN("ok\n"));

    test_printf("update");
    result = kvs->set(kvs, key2, key2_value1, strlen(key2_value1), 0);
    assert(result == KVSTORE_SUCCESS);
    result = kvs->get(kvs, key2, value, sizeof(value), &value_size, 0);
    assert(result == KVSTORE_SUCCESS);
    assert(strlen(key2_value1) == value_size);
    assert(memcmp(key2_value1, value, value_size) == 0);
    printf(COLOR_GREEN("ok\n"));

    test_printf("delete");
    result = kvs->delete(kvs, key2);
    assert(result == KVSTORE_SUCCESS);
    result = kvs->get(kvs, key2, value, sizeof(value), &value_size, 0);
    assert(result == KVSTORE_ERROR_ITEM_NOT_FOUND);
    printf(COLOR_GREEN("ok\n"));
}

static void test_garbage_collection(kvs_t *kvs) {
    kvs_logkvs_context_t *context = kvs->context;

    test_printf("garbage collection");

    int result;

    assert(context->active_bank == 0);
    assert(context->bank_version == 1);
    while (true) {
        result = kvs->set(kvs, key3, key3_value1, strlen(key3_value1), 0);
        assert(result == KVSTORE_SUCCESS);
        if (context->active_bank != 0) {
            break;
        }
    }
    assert(context->active_bank == 1);
    assert(context->bank_version == 2);
    while (true) {
        result = kvs->set(kvs, key3, key3_value1, strlen(key3_value1), 0);
        assert(result == KVSTORE_SUCCESS);
        if (context->active_bank != 1) {
            break;
        }
    }
    assert(context->active_bank == 0);
    assert(context->bank_version == 3);

    printf(COLOR_GREEN("ok\n"));
}

static void test_various_size_key(kvs_t *kvs) {
    int result;
    char key[256] = {0};
    const char value[] = "value";
    char buffer[4096];
    size_t value_size;

    test_printf("1-byte key");
    result = kvs->set(kvs, "1", value, strlen(value), 0);
    assert(result == KVSTORE_SUCCESS);
    result = kvs->get(kvs, "1", buffer, sizeof(buffer), &value_size, 0);
    assert(result == KVSTORE_SUCCESS);
    result = kvs->delete(kvs, "1");
    assert(result == KVSTORE_SUCCESS);
    printf(COLOR_GREEN("ok\n"));

    test_printf("128-byte key");
    for (size_t i = 0; i < 128; i++)
        key[i] = 'a' + (i % 26);
    key[128] = '\0';
    result = kvs->set(kvs, key, value, strlen(value), 0);
    assert(result == KVSTORE_SUCCESS);
    result = kvs->get(kvs, key, buffer, sizeof(buffer), &value_size, 0);
    assert(result == KVSTORE_SUCCESS);
    result = kvs->delete(kvs, key);
    assert(result == KVSTORE_SUCCESS);
    printf(COLOR_GREEN("ok\n"));

    test_printf(">128-byte key");
    for (size_t i = 0; i < 129; i++)
        key[i] = 'a' + (i % 26);
    key[129] = '\0';
    result = kvs->set(kvs, key, value, strlen(value), 0);
    assert(result == KVSTORE_ERROR_INVALID_ARGUMENT);
    result = kvs->get(kvs, key, buffer, sizeof(buffer), &value_size, 0);
    assert(result == KVSTORE_ERROR_INVALID_ARGUMENT);
    result = kvs->delete(kvs, key);
    assert(result == KVSTORE_ERROR_INVALID_ARGUMENT);
    printf(COLOR_GREEN("ok\n"));
}

static void test_various_size_value(kvs_t *kvs) {
    int result;
    char key[] = "various-value";
    char value[4*1024];
    char buffer[4*1024];
    for (size_t size = 1; size < 4096; size *= 2) {
        test_printf("%u-byte value", size);

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

        printf(COLOR_GREEN("ok\n"));
    }
}

static void test_various_size_value_garbage_collection(kvs_t *kvs) {
    kvs_logkvs_context_t *context = kvs->context;

    int result;

    char key[] = "key";
    char value[4096];
    char buffer[4096];
    for (size_t size = 1; size <= sizeof(value); size *= 2) {
        test_printf("%u byte value garbage collection", size);

        for (size_t i = 0; i < size; i++)
            value[i] = 'a' + (i % 26);

        uint32_t last_bank = context->active_bank;
        while (true) {
            result = kvs->set(kvs, key, value, size, 0);
            assert(result == KVSTORE_SUCCESS);
            if (context->active_bank != last_bank) {
                break;
            }
        }
        size_t buf_size;
        result = kvs->get(kvs, key, buffer, sizeof(buffer), &buf_size, 0);
        assert(result == KVSTORE_SUCCESS);
        assert(size == buf_size);
        assert(memcmp(value, buffer, size) == 0);

        printf(COLOR_GREEN("ok\n"));
    }
}

void test_kvstore_logkvs(void) {
#if PICO_ON_DEVICE
    printf("Log Key-Value Store, Flash memory:\n");
#else
    printf("Log Key-Value Store, Heap memory:\n");
#endif

    blockdevice_t *device = blockdevice_test_create();
    setup(device);

    kvs_t *kvs = kvs_logkvs_create(device);
    assert(kvs != NULL);

    test_basic_crud(kvs);
    test_garbage_collection(kvs);
    test_various_size_key(kvs);
    test_various_size_value(kvs);
    test_various_size_value_garbage_collection(kvs);

    cleanup(device);
    kvs_logkvs_free(kvs);
    blockdevice_test_free(device);
}
