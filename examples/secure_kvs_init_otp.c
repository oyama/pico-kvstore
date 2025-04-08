#include <string.h>
#include "kvstore.h"
#include "kvstore_logkvs.h"
#include "kvstore_securekvs.h"
#include "blockdevice/flash.h"
#include "pico/btstack_flash_bank.h"
#include "hardware/regs/addressmap.h"

#define KVSTORE_BANK_DEFAULT_SIZE  (128 * 1024)
#define KVSTORE_BANK_OFFSET        (PICO_FLASH_BANK_STORAGE_OFFSET - KVSTORE_BANK_DEFAULT_SIZE)

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


#define HEAD_OF_OTP_SECRET_KEY  (0xc08 * 2)
#define OTP_ROW_SIZE            2
#define SECRET_KEY_SIZE         16

/*
** RP2350 Read 128-bit secret key starting at line 0xc08 of OTP
*/
static int secretkey_loader_for_otp(uint8_t *key) {
    const uint16_t *otp = (uint16_t *)(OTP_DATA_GUARDED_BASE + HEAD_OF_OTP_SECRET_KEY);
    for (size_t i = 0; i < SECRET_KEY_SIZE / OTP_ROW_SIZE; i++) {
        key[i * 2] = (*(otp + i) & 0xFF00) >> 8;
        key[i * 2 + 1] = (*(otp + i) & 0xFF);
    }
    return 0;
}

bool __attribute__((weak)) kvs_init(void) {
    print_debug("Create a block device that uses 0x%08x->0x%08x(%uKB) areas of flash memory\n",
                XIP_BASE + KVSTORE_BANK_OFFSET,
                XIP_BASE + KVSTORE_BANK_OFFSET + KVSTORE_BANK_DEFAULT_SIZE,
                KVSTORE_BANK_DEFAULT_SIZE / 1024);
    blockdevice_t *bd = blockdevice_flash_create(KVSTORE_BANK_OFFSET, KVSTORE_BANK_DEFAULT_SIZE);

    print_debug("Create a Log structured Key-Value Store that uses a block device\n");
    kvs_t *underlying_kvs = kvs_logkvs_create(bd);

    print_debug("Create a Secure Key-Value Store that uses a Log structured KVS\n");
    kvs_t *kvs = kvs_securekvs_create(underlying_kvs, secretkey_loader_for_otp);

    print_debug("Assign to global Key-Value Store\n");
    kvs_assign(kvs);

    return true;
}
