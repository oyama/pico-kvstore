/*
 * Copyright 2025, Hiroyuki OYAMA
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */
#pragma once

/** \defgroup blockdevice_fault blockdevice_fault
 *  \ingroup blockdevice
 *  \brief blockdevice that fault on specified conditions
 */
#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include "blockdevice/blockdevice.h"

typedef struct {
    size_t size;
    blockdevice_t *underlying;
    uint32_t program_count;
    uint32_t fault_from;
} blockdevice_fault_config_t;

/*! \brief Create a block device that fault on specified conditions
 * \ingroup blockdevice_fault
 *
 * Create a block device object that fault on specified conditions.
 *
 * \param underlying original block device.
 * \return Block device object. Returnes NULL in case of failure.
 * \retval NULL Failed to create block device object.
 */
blockdevice_t *blockdevice_fault_create(blockdevice_t *underlying);

/*! \brief Release the fault device.
 * \ingroup blockdevice_fault
 *
 * \param device Block device object.
 */
void blockdevice_fault_free(blockdevice_t *device);

uint32_t blockdevice_fault_program_count(blockdevice_t *device);
void blockdevice_fault_set_fault_from(blockdevice_t *device, uint32_t program_count);

#ifdef __cplusplus
}
#endif
