/*
 * Copyright 2025, Hiroyuki OYAMA
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */
#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include "kvstore.h"
#include "blockdevice/blockdevice.h"

#define KVSTORE_NUM_BANK 2

typedef struct {
    uint32_t address;
    size_t   size;
} kvs_bank_params_t;

typedef struct {
    uint32_t  hash;
    uint32_t bd_offset;
} ram_index_entry_t;

typedef struct {
    uint32_t magic;
    uint16_t header_size;
    uint16_t revision;
    uint32_t flags;
    uint16_t key_size;
    uint32_t data_size;
    uint32_t crc;
} record_header_t;

typedef struct {
    size_t num_keys;
    size_t size;
    size_t max_keys;

    blockdevice_t *device;
    ram_index_entry_t *ram_index;
    char *key_buf;
    uint8_t *work_buf;
    size_t work_buf_size;
    uint32_t free_space_offset;
    uint32_t master_record_offset;
    uint32_t master_record_size;
    uint8_t active_bank;
    uint16_t bank_version;
    kvs_bank_params_t bank_params[KVSTORE_NUM_BANK];
    kvs_find_t *iterator_table[MAX_OPEN_ITERATORS];

    void *inc_set_handle;
} kvs_logkvs_context_t;

kvs_t *kvs_logkvs_create(blockdevice_t *device);
void kvs_logkvs_free(kvs_t *kvs);

#ifdef __cplusplus
}
#endif
