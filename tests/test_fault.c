#include <assert.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include "pico/stdlib.h"
#include "blockdevice_fault.h"
#include "kvstore_logkvs.h"
#include "utils.h"

#define COLOR_GREEN(format)  ("\e[32m" format "\e[0m")



static void setup(blockdevice_t *device) {
    size_t length = device->size(device);
    device->erase(device, 0, length);
}

void test_set_fault(void) {
    test_printf("set fault");

    blockdevice_t *underlying = blockdevice_test_create();
    blockdevice_t *device = blockdevice_fault_create(underlying);
    setup(device);
    kvs_t *kvs = kvs_logkvs_create(device);

    const char KEY1[] = "key1";
    const char VALUE1[] = "normal operation#1";
    const char KEY2[] = "key2";
    const char VALUE2[] = "normal operation#2";
    const char VALUE3[] = "normal operation#3";

    int res = kvs->set(kvs, KEY1, VALUE1, strlen(VALUE1), 0);
    assert(res == KVSTORE_SUCCESS);
    res = kvs->set(kvs, KEY2, VALUE2, strlen(VALUE2), 0);
    assert(res == KVSTORE_SUCCESS);

    uint32_t program_count = blockdevice_fault_program_count(device);
    blockdevice_fault_set_fault_from(device, program_count + 1);
    res = kvs->set(kvs, KEY2, VALUE3, strlen(VALUE3), 0);
    assert(res == KVSTORE_ERROR_WRITE_FAILED);

    char buffer[128];
    size_t size;
    res = kvs->get(kvs, KEY1, buffer, sizeof(buffer), &size, 0);
    assert(res == KVSTORE_SUCCESS);
    assert(memcmp(buffer, VALUE1, strlen(VALUE1)) == 0);

    res = kvs->get(kvs, KEY2, buffer, sizeof(buffer), &size, 0);
    assert(res == KVSTORE_SUCCESS);
    assert(memcmp(buffer, VALUE2, strlen(VALUE2)) == 0);

    kvs_logkvs_free(kvs);
    blockdevice_fault_free(device);
    blockdevice_test_free(underlying);

    printf(COLOR_GREEN("ok\n"));
}

void test_garbage_collection_fault(void) {
    test_printf("garbage collection fault");

    blockdevice_t *underlying = blockdevice_test_create();
    blockdevice_t *device = blockdevice_fault_create(underlying);
    setup(device);
    kvs_t *kvs = kvs_logkvs_create(device);
    kvs_logkvs_context_t *context = kvs->context;

    char KEY1[] = "key1";
    char value[1024];
    for (size_t i = 0; i < sizeof(value); i++)
        value[i] = 'a' + (i % 26);

    int result;
    uint8_t active_bank = context->active_bank;

    for (size_t i = 0; i < 629; i++) {
        result = kvs->set(kvs, KEY1, value, sizeof(value), 0);
        assert(result == KVSTORE_SUCCESS);
    }
    assert(active_bank == context->active_bank);

    // enable fault mode
    uint32_t program_count = blockdevice_fault_program_count(device);
    blockdevice_fault_set_fault_from(device, program_count + 1);
    result = kvs->set(kvs, KEY1, value, sizeof(value), 0);
    assert(result == KVSTORE_ERROR_WRITE_FAILED);
    assert(active_bank == context->active_bank);

    // disable fault mode
    blockdevice_fault_set_fault_from(device, 0);
    active_bank = context->active_bank;
    result = kvs->set(kvs, KEY1, value, sizeof(value), 0);
    assert(result == KVSTORE_SUCCESS);
    assert(active_bank != context->active_bank);

    char buffer[1024];
    size_t size;
    result = kvs->get(kvs, KEY1, buffer, sizeof(buffer), &size, 0);
    assert(result == KVSTORE_SUCCESS);
    assert(memcmp(buffer, value, sizeof(value)) == 0);

    kvs_logkvs_free(kvs);
    blockdevice_fault_free(device);
    blockdevice_test_free(underlying);

    printf(COLOR_GREEN("ok\n"));
}

void test_fault(void) {
    printf("KVStore Fault Simulation:\n");
    test_set_fault();
    test_garbage_collection_fault();
}
