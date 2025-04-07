/*
 * Copyright 2025, Hiroyuki OYAMA
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "kvstore.h"

static kvs_t *global_kvs = NULL;

kvs_t *kvs_global_instance(void) { return global_kvs; }

void kvs_assign(kvs_t *kvs) { global_kvs = kvs; }

int kvs_set(const char *key, const void *value, size_t size, uint32_t flags) {
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
