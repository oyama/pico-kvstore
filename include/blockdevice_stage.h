/*
 * Copyright 2025, Hiroyuki OYAMA
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */
#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include "blockdevice/blockdevice.h"

blockdevice_t *blockdevice_stage_create(blockdevice_t *bd);
void blockdevice_stage_free(blockdevice_t *device);

#ifdef __cplusplus
}
#endif
