#include <stdio.h>
#include <string.h>
#include "pico/btstack_flash_bank.h"
#include "pico/stdlib.h"
#include "blockdevice/flash.h"
#include "kvstore_logkvs.h"
#include "kvstore_securekvs.h"

#define FLASH_START_AT       (512 * 1024)

#define KVSTORE_BANK_DEFAULT_SIZE  (128 * 1024)
#define KVSTORE_BANK_OFFSET        (PICO_FLASH_BANK_STORAGE_OFFSET - KVSTORE_BANK_DEFAULT_SIZE)

static void print_progress(const char *label, size_t current, size_t total) {
    int num_dots = (int)((double)current / total * (50 - strlen(label)));
    int num_spaces = (50 - strlen(label)) - num_dots;

    printf("\r%s ", label);
    for (int i = 0; i < num_dots; i++) {
        printf(".");
    }
    for (int i = 0; i < num_spaces; i++) {
        printf(" ");
    }
    printf(" %zu/%zu ", current, total);
    fflush(stdout);
}

static void CRUD_latency(void) {
    for (size_t record_size = 1000; record_size <= 5000; record_size += 1000) {
        blockdevice_t *flash = blockdevice_flash_create(FLASH_START_AT, 1024 * 1024 * 1);
        flash->erase(flash, 0, 1024 * 1024 * 1);
        kvs_t *kvs = kvs_logkvs_create(flash);

        char buffer[1024] = {0};
        memset(buffer, '0', sizeof(buffer));
        char label[64];
        char key[] = "0000000000000000";
        sprintf(label, "Prepare %u records", record_size);

        for (size_t i = 0; i <= record_size; i++) {
            sprintf(key, "%016u", i);
            int rc = kvs->set(kvs, key, buffer, sizeof(key), 0);
            if (rc != KVSTORE_SUCCESS) {
                printf("Set rc=%d\n", rc);
                break;
            }
            print_progress(label, i, record_size);
        }
        sprintf(label, "Latency of Set with %u records", record_size);
        absolute_time_t start_at = get_absolute_time();
        for (size_t i = record_size; i <= record_size + 100; i++) {
            sprintf(key, "%016u", i);
            int rc = kvs->set(kvs, key, buffer, sizeof(key), 0);
            if (rc != KVSTORE_SUCCESS) {
                printf("Set rc=%d\n", rc);
                break;
            }
            print_progress(label, i - record_size, 100);
        }
        double duration = (double)absolute_time_diff_us(start_at, get_absolute_time()) / 1000 / 1000;
        printf(" %.1f ops/sec(%.4f sec/ops)\n", ((double)100 / duration), (duration / (double)100));

        size_t actual_value_size;
        sprintf(label, "Latency of Get with %u records", record_size);
        start_at = get_absolute_time();
        for (size_t i = record_size; i <= record_size + 100; i++) {
            sprintf(key, "%016u", i);
            int rc = kvs->get(kvs, key, buffer, sizeof(buffer), &actual_value_size, 0);
            if (rc != KVSTORE_SUCCESS) {
                printf("Get rc=%d\n", rc);
                break;
            }
            print_progress(label, i - record_size, 100);
        }
        duration = (double)absolute_time_diff_us(start_at, get_absolute_time()) / 1000 / 1000;
        printf(" %.1f ops/sec(%.4f sec/ops)\n", ((double)100 / duration), (duration / (double)100));

        sprintf(label, "Latency of Delete with %u records", record_size);
        start_at = get_absolute_time();
        for (size_t i = record_size; i <= record_size + 100; i++) {
            sprintf(key, "%016u", i);
            int rc = kvs->delete(kvs, key);
            if (rc != KVSTORE_SUCCESS) {
                printf("Delete rc=%d\n", rc);
                break;
            }
            print_progress(label, i - record_size, 100);
        }
        duration = (double)absolute_time_diff_us(start_at, get_absolute_time()) / 1000 / 1000;
        printf(" %.1f ops/sec(%.4f sec/ops)\n", ((double)100 / duration), (duration / (double)100));

        kvs_logkvs_free(kvs);
        blockdevice_flash_free(flash);
    }
}

static void garbage_collection_latency(void) {
    for (size_t storage_size = 8; storage_size <= 1024; storage_size *= 2) {
        blockdevice_t *flash = blockdevice_flash_create(FLASH_START_AT, storage_size * 1024);
        flash->erase(flash, 0, storage_size * 1024);
        kvs_t *kvs = kvs_logkvs_create(flash);
        kvs_logkvs_context_t *context = kvs->context;

        char buffer[1024] = {0};
        size_t test_size = (storage_size * 1024 / 2 / 30) * 10;
        char label[64];
        sprintf(label, "Garbage collection Latency with %uKB storage", storage_size);

        char key[] = "000000000000000000000000000000000";
        double total_latency = 0.0;
        int num_garbage_collection = 0;
        double worst_latency = 0.0;
        int last_version = 1;
        for (size_t i = 1; i <= test_size; i++) {
            sprintf(key, "%016u", i);
            absolute_time_t start_at = get_absolute_time();
            int rc = kvs->set(kvs, key, buffer, 16, 0);
            double duration = (double)absolute_time_diff_us(start_at, get_absolute_time()) / 1000 / 1000;
            if (rc != KVSTORE_SUCCESS) {
                printf("Set rc=%d\n", rc);
                break;
            }
            rc = kvs->delete(kvs, key);
            if (rc != KVSTORE_SUCCESS) {
                printf("Delete rc=%d\n", rc);
                break;
            }

            if (context->bank_version != last_version) {
                total_latency += duration;
                num_garbage_collection++;
                if (worst_latency < duration)
                    worst_latency = duration;

                last_version = context->bank_version;
            }

            print_progress(label, i, test_size);
        }
        printf(" %.4f sec/gc, (n=%d, worst %.4f sec)\n", (total_latency / (double)num_garbage_collection), num_garbage_collection, worst_latency);

        kvs_logkvs_free(kvs);
        blockdevice_flash_free(flash);
    }
}

static void secure_CRUD_latency(void) {
    for (size_t record_size = 1000; record_size <= 5000; record_size += 1000) {
        blockdevice_t *flash = blockdevice_flash_create(FLASH_START_AT, 1024 * 1024 * 1);
        flash->erase(flash, 0, 1024 * 1024 * 1);
        kvs_t *underlying_kvs = kvs_logkvs_create(flash);
        kvs_t *kvs = kvs_securekvs_create(underlying_kvs, NULL);

        char buffer[1024] = {0};
        memset(buffer, '0', sizeof(buffer));
        char label[64];
        char key[] = "0000000000000000";
        sprintf(label, "Prepare %u records in Secure KVS", record_size);

        for (size_t i = 0; i <= record_size; i++) {
            sprintf(key, "%016u", i);
            int rc = kvs->set(kvs, key, buffer, sizeof(key), 0);
            if (rc != KVSTORE_SUCCESS) {
                printf("Set rc=%d\n", rc);
                break;
            }
            print_progress(label, i, record_size);
        }
        sprintf(label, "Latency of Set with %u records in Secure KVS", record_size);
        absolute_time_t start_at = get_absolute_time();
        for (size_t i = record_size; i <= record_size + 100; i++) {
            sprintf(key, "%016u", i);
            int rc = kvs->set(kvs, key, buffer, sizeof(key), KVSTORE_REQUIRE_CONFIDENTIALITY_FLAG);
            if (rc != KVSTORE_SUCCESS) {
                printf("Set rc=%d\n", rc);
                break;
            }
            print_progress(label, i - record_size, 100);
        }
        double duration = (double)absolute_time_diff_us(start_at, get_absolute_time()) / 1000 / 1000;
        printf(" %.1f ops/sec(%.4f sec/ops)\n", ((double)100 / duration), (duration / (double)100));

        size_t actual_value_size;
        sprintf(label, "Latency of Get with %u records in Secure KVS", record_size);
        start_at = get_absolute_time();
        for (size_t i = record_size; i <= record_size + 100; i++) {
            sprintf(key, "%016u", i);
            int rc = kvs->get(kvs, key, buffer, sizeof(buffer), &actual_value_size, 0);
            if (rc != KVSTORE_SUCCESS) {
                printf("Get rc=%d\n", rc);
                break;
            }
            print_progress(label, i - record_size, 100);
        }
        duration = (double)absolute_time_diff_us(start_at, get_absolute_time()) / 1000 / 1000;
        printf(" %.1f ops/sec(%.4f sec/ops)\n", ((double)100 / duration), (duration / (double)100));

        sprintf(label, "Latency of Delete with %u records in Secure KVS", record_size);
        start_at = get_absolute_time();
        for (size_t i = record_size; i <= record_size + 100; i++) {
            sprintf(key, "%016u", i);
            int rc = kvs->delete(kvs, key);
            if (rc != KVSTORE_SUCCESS) {
                printf("Delete rc=%d\n", rc);
                break;
            }
            print_progress(label, i - record_size, 100);
        }
        duration = (double)absolute_time_diff_us(start_at, get_absolute_time()) / 1000 / 1000;
        printf(" %.1f ops/sec(%.4f sec/ops)\n", ((double)100 / duration), (duration / (double)100));

        kvs_securekvs_free(kvs);
        kvs_logkvs_free(underlying_kvs);
        blockdevice_flash_free(flash);
    }
}

int main(void) {
    stdio_init_all();

    printf("Start benchmark test\n");

    CRUD_latency();
    secure_CRUD_latency();
    garbage_collection_latency();

    printf("done\n");
    while (true) {
        tight_loop_contents();
    }
    return 0;
}
