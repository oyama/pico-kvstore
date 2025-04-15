/*
 * Copyright 2025, Hiroyuki OYAMA
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */
#pragma once

/** \defgroup blockdevice_fault blockdevice_fault
 *  \ingroup blockdevice
 *  \brief Heap memory block device
 */
#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include "blockdevice/blockdevice.h"

/*! \brief Create RAM heap memory block device
 * \ingroup blockdevice_heap
 *
 * Create a block device object that uses RAM heap memory.  The size of heap memory allocated to the block device is specified by size.
 *
 * \param size Size in bytes to be allocated to the block device.
 * \return Block device object. Returnes NULL in case of failure.
 * \retval NULL Failed to create block device object.
 */
blockdevice_t *blockdevice_fault_create(size_t size);

/*! \brief Release the heap memory device.
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
