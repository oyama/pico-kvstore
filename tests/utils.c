#include <stdarg.h>
#include <stdio.h>
#include "blockdevice/blockdevice.h"
#include "utils.h"

#if PICO_ON_DEVICE
#include "blockdevice/flash.h"
#include "hardware/flash.h"
#else
#include "blockdevice/heap.h"
#endif

#if PICO_ON_DEVICE

#ifndef PICO_FLASH_BANK_TOTAL_SIZE
#define PICO_FLASH_BANK_TOTAL_SIZE (FLASH_SECTOR_SIZE * 2u)
#endif
#ifndef PICO_FLASH_BANK_STORAGE_OFFSET
#define PICO_FLASH_BANK_STORAGE_OFFSET (PICO_FLASH_SIZE_BYTES - PICO_FLASH_BANK_TOTAL_SIZE)
#endif

#define TEST_STORAGE_SIZE    (128 * 1024)
#define TEST_STORAGE_OFFSET  (PICO_FLASH_BANK_STORAGE_OFFSET - TEST_STORAGE_SIZE)

#else // !PICO_ON_DEVICE

#define TEST_STORAGE_SIZE    (128 * 1024)
#endif // !PICO_ON_DEVICE


void test_printf(const char *format, ...) {
    va_list args;
    va_start(args, format);
    int n = vprintf(format, args);
    va_end(args);

    printf(" ");
    for (size_t i = 0; i < 50 - (size_t)n; i++)
        printf(".");
}

blockdevice_t *blockdevice_test_create(void) {
#if PICO_ON_DEVICE
    return blockdevice_flash_create(TEST_STORAGE_OFFSET, TEST_STORAGE_SIZE);
#else
    return blockdevice_heap_create(TEST_STORAGE_SIZE);
#endif
}

void blockdevice_test_free(blockdevice_t *bd) {
#if PICO_ON_DEVICE
    blockdevice_flash_free(bd);
#else
    blockdevice_heap_free(bd);
#endif
}
