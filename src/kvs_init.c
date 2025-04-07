/*
 * Copyright 2025, Hiroyuki OYAMA
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "blockdevice/flash.h"
#include "kvstore.h"
#include "kvstore_logkvs.h"
#include "pico/btstack_flash_bank.h"

#define KVSTORE_BANK_DEFAULT_SIZE (128 * 1024)
#define KVSTORE_BANK_OFFSET (PICO_FLASH_BANK_STORAGE_OFFSET - KVSTORE_BANK_DEFAULT_SIZE)

#ifdef KVSTORE_DEBUG
#include <stdarg.h>
#include <stdio.h>
static inline void print_debug(const char *format, ...) {
    va_list args;
    va_start(args, format);
    vprintf(format, args);
    va_end(args);
}
#else
static inline void print_debug(const char *format, ...) { (void)format; }
#endif

bool __attribute__((weak)) kvs_init(void) {
    print_debug("Create a block device that uses 0x%08x->0x%08x(%uKB) areas of flash memory\n",
                XIP_BASE + KVSTORE_BANK_OFFSET,
                XIP_BASE + KVSTORE_BANK_OFFSET + KVSTORE_BANK_DEFAULT_SIZE,
                KVSTORE_BANK_DEFAULT_SIZE / 1024);
    blockdevice_t *bd = blockdevice_flash_create(KVSTORE_BANK_OFFSET, KVSTORE_BANK_DEFAULT_SIZE);

    print_debug("Create a Log structured Key-Value Store that uses a block device\n");
    kvs_t *kvs = kvs_logkvs_create(bd);

    print_debug("Assign to global Key-Value Store\n");
    kvs_assign(kvs);

    return true;
}
