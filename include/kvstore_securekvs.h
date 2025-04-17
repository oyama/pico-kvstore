/*
 * Copyright 2025, Hiroyuki OYAMA
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */
#pragma once

#include "kvstore.h"
#include "mbedtls/gcm.h"

#define ENCRYPT_BLOCK_SIZE 16
#define IV_SIZE 16

typedef struct {
    uint16_t metadata_size;
    uint16_t revision;
    uint32_t data_size;
    uint32_t create_flags;
    uint8_t iv[IV_SIZE];
} record_metadata_t;

typedef struct {
    record_metadata_t metadata;
    char *key;
    uint32_t offset_in_data;
    uint8_t ctr_buf[ENCRYPT_BLOCK_SIZE];
    mbedtls_gcm_context *gcm_ctx;
    void *underlying_handle;
} inc_set_handle_t;

typedef struct {
    kvs_t *underlying_kvs;
    int (*secretkey_loader)(uint8_t *key);
    uint8_t *scratch_buf;
    inc_set_handle_t *ih;
} kvs_securekvs_context_t;


kvs_t *kvs_securekvs_create(kvs_t *underlying_kvs,
                            int (*secretkey_loader)(uint8_t *key));
void kvs_securekvs_free(kvs_t *kvs);
