/*
 * Copyright 2025, Hiroyuki OYAMA
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "kvstore.h"

static kvs_t *global_kvs = NULL;

kvs_t *kvs_global_instance(void) { return global_kvs; }

void kvs_assign(kvs_t *kvs) { global_kvs = kvs; }


int kvs_set(const char *key, const void *value, size_t size) {
    kvs_t *kvs = global_kvs;
    if (kvs == NULL) {
        return -1;
    }
    return kvs->set(kvs, key, value, size, 0);
}

int kvs_set_flag(const char *key, const void *value, size_t size, uint32_t flags) {
    kvs_t *kvs = global_kvs;
    if (kvs == NULL) {
        return -1;
    }
    return kvs->set(kvs, key, value, size, flags);
}

int kvs_get(const char *key, void *value, size_t buffer_size, size_t *value_size) {
    kvs_t *kvs = global_kvs;
    if (kvs == NULL) {
        return -1;
    }
    return kvs->get(kvs, key, value, buffer_size, value_size, 0);
}

int kvs_get_str(const char *key, char *value, size_t buffer_size) {
    size_t value_size;
    int ret = kvs_get(key, value, buffer_size, &value_size);
    if (ret != KVSTORE_SUCCESS)
        return ret;
    if (value_size < buffer_size)
        value[value_size] = '\0';
    else
        value[buffer_size] = '\0';
    return KVSTORE_SUCCESS;
}

int kvs_delete(const char *key) {
    kvs_t *kvs = global_kvs;
    if (kvs == NULL) {
        return -1;
    }
    return kvs->delete(kvs, key);
}

int kvs_find(const char *prefix, kvs_find_t *ctx) {
    kvs_t *kvs = global_kvs;
    if (kvs == NULL)
        return -1;
    return kvs->find(kvs, prefix, ctx);
}

int kvs_find_next(kvs_find_t *ctx, const char *key, size_t key_size) {
    kvs_t *kvs = global_kvs;
    if (kvs == NULL)
        return -1;
    return kvs->find_next(kvs, ctx, key, key_size);
}

int kvs_find_close(kvs_find_t *ctx) {
    kvs_t *kvs = global_kvs;
    if (kvs == NULL)
        return -1;
    return kvs->find_close(kvs, ctx);
}

char *kvs_strerror(int errnum) {
    const char *str = "";
    switch (errnum) {
        case KVSTORE_SUCCESS:
            str = "";
            break;
        case KVSTORE_ERROR_INVALID_DATA_DETECTED:
            str = "invalid data detected";
            break;
        case KVSTORE_ERROR_INVALID_SIZE:
            str = "invalid size";
            break;
        case KVSTORE_ERROR_INVALID_ARGUMENT:
            str = "invalid argument";
            break;
        case KVSTORE_ERROR_ITEM_NOT_FOUND:
            str = "item not found";
            break;
        case KVSTORE_ERROR_READ_FAILED:
            str = "read failed";
            break;
        case KVSTORE_ERROR_WRITE_FAILED:
            str = "write failed";
            break;
        case KVSTORE_ERROR_MEDIA_FULL:
            str = "media full";
            break;
        case KVSTORE_ERROR_OUT_OF_RESOURCES:
            str = "out of resources";
            break;
        case KVSTORE_ERROR_WRITE_PROTECTED:
            str = "write protected";
            break;
        case KVSTORE_ERROR_FAILED_OPERATION:
            str = "failed operation";
            break;
        case KVSTORE_ERROR_AUTHENTICATION_FAILED:
            str = "authentication failed";
            break;
        default:
            str = "unknown error";
    }
    return (char *)str;
}
