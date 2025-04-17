/*
 * Copyright 2025, Hiroyuki OYAMA
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */
#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include "blockdevice/blockdevice.h"


typedef enum {
    KVSTORE_SUCCESS = 0,
    KVSTORE_ERROR_INVALID_DATA_DETECTED,
    KVSTORE_ERROR_INVALID_SIZE,
    KVSTORE_ERROR_INVALID_ARGUMENT,
    KVSTORE_ERROR_ITEM_NOT_FOUND,
    KVSTORE_ERROR_READ_FAILED,
    KVSTORE_ERROR_WRITE_FAILED,
    KVSTORE_ERROR_MEDIA_FULL,
    KVSTORE_ERROR_OUT_OF_RESOURCES,
    KVSTORE_ERROR_WRITE_PROTECTED,
    KVSTORE_ERROR_FAILED_OPERATION,
    KVSTORE_ERROR_AUTHENTICATION_FAILED,
} kvs_error_t;

typedef enum {
    KVSTORE_WRITE_ONCE_FLAG                = (1 << 0),
    KVSTORE_REQUIRE_CONFIDENTIALITY_FLAG   = (1 << 1),
    KVSTORE_REQUIRE_REPLAY_PROTECTION_FLAG = (1 << 3),
} create_flags_t;

typedef struct {
    size_t size;
    uint32_t flags;
} kvs_info_t;

#define MAX_OPEN_ITERATORS  16

typedef struct {
    const char *prefix;
    int iterator_num;
    uint32_t ram_index_ind;
} kvs_find_t;

typedef struct {
    void *handle;
} kvs_inc_set_handle_t;

typedef struct kvstore {
    int (*init)(struct kvstore *kvs);
    int (*deinit)(struct kvstore *kvs);
    int (*set)(struct kvstore *kvs, const char *key, const void *value, size_t size, uint32_t flags);
    int (*get)(struct kvstore *kvs, const char *key, void *buffer, size_t buffer_size, size_t *value_size, size_t offset);
    int (*delete)(struct kvstore *kvs, const char *key);
    int (*find)(struct kvstore *kvs, const char *prefix, kvs_find_t *ctx);
    int (*find_next)(struct kvstore *kvs, kvs_find_t *ctx, const char *key, size_t key_size);
    int (*find_close)(struct kvstore *kvs, kvs_find_t *ctx);

    int (*set_start)(struct kvstore *kvs, kvs_inc_set_handle_t *handle, const char *key, size_t final_data_size, uint32_t flags);
    int (*set_add_data)(struct kvstore *kvs, kvs_inc_set_handle_t *handle, const void *value_data, size_t data_size);
    int (*set_finalize)(struct kvstore *kvs, kvs_inc_set_handle_t *handle);

    int (*get_info)(struct kvstore *kvs, const char *key, kvs_info_t *info);

    void *context;
    size_t handle_size;
    bool is_initialized;
} kvs_t;

bool kvs_init(void);
kvs_t *kvs_global_instance(void);
void kvs_assign(kvs_t *kvs);
int kvs_set(const char *key, const void *value, size_t size);
int kvs_set_flag(const char *key, const void *value, size_t size, uint32_t flags);
int kvs_get(const char *key, void *value, size_t buffer_size, size_t *value_size);
int kvs_get_str(const char *key, char *value, size_t buffer_size);
int kvs_delete(const char *key);
int kvs_find(const char *prefix, kvs_find_t *ctx);
int kvs_find_next(kvs_find_t *ctx, const char *key, size_t key_size);
int kvs_find_close(kvs_find_t *ctx);

char *kvs_strerror(int error);

#ifdef __cplusplus
}
#endif
