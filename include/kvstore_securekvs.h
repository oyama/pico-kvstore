/*
 * Copyright 2025, Hiroyuki OYAMA
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */
#pragma once

#include "kvstore.h"


kvs_t *kvs_securekvs_create(kvs_t *underlying_kvs,
                            int (*secretkey_loader)(uint8_t *key));
void kvs_securekvs_free(kvs_t *kvs);
