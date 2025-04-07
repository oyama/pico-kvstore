/*
 * Copyright 2025, Hiroyuki OYAMA
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "kvstore_logkvs.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "blockdevice/blockdevice.h"
#include "blockdevice_stage.h"
#include "crc32_ansi.h"

static const uint32_t kvstore_magic = 0x4C534B56;
static const char *master_rec_key = "LSKV";

static const uint32_t DELETE_FLAG = (1UL << 31);
static const uint32_t internal_flags = DELETE_FLAG;
static const uint32_t supported_flags = KVSTORE_WRITE_ONCE_FLAG |
                                        KVSTORE_REQUIRE_CONFIDENTIALITY_FLAG |
                                        KVSTORE_REQUIRE_REPLAY_PROTECTION_FLAG;

typedef struct {
    uint16_t version;
    uint16_t kvstore_revision;
} master_record_data_t;

typedef enum {
    KVSTORE_BANK_STATE_NONE = 0,
    KVSTORE_BANK_STATE_ERASED,
    KVSTORE_BANK_STATE_INVALID,
    KVSTORE_BANK_STATE_VALID,
} bank_state_t;

typedef struct {
    record_header_t header;
    bd_size_t bd_base_offset;
    bd_size_t bd_curr_offset;
    uint32_t offset_in_data;
    uint32_t ram_index_ind;
    uint32_t hash;
    bool new_key;
} inc_set_handle_t;

static const uint32_t MAX_KEY_SIZE = 128;
static const size_t MIN_WORK_BUF_SIZE = 64;

static int _set(kvs_t *kvs, const char *key, const void *buffer, size_t size, uint32_t flags);

static inline uint32_t align_up(uint32_t val, uint32_t size) {
    return (((val - 1) / size) + 1) * size;
}

static inline uint32_t align_down(uint64_t val, uint64_t size) { return (((val) / size)) * size; }

static int32_t record_size(kvs_t *kvs, const char *key, uint32_t data_size) {
    kvs_logkvs_context_t *context = kvs->context;

    return align_up(sizeof(record_header_t), context->device->program_size) +
           align_up(strlen(key) + data_size, context->device->program_size);
}

static uint32_t calc_crc(uint32_t init_crc, uint32_t size, const void *data_buf) {
    uint32_t crc = crc32_ansi_update_block(init_crc, data_buf, size);
    return crc;
}

#define ROUND_UP(x, y) (((x) + (y - 1)) & ~(y - 1))
#ifndef MIN
#define MIN(a, b) ((a < b) ? a : b)
#endif

#ifndef MAX
#define MAX(a, b) ((a < b) ? b : a)
#endif

static void update_bank_params(kvs_t *kvs) {
    kvs_logkvs_context_t *context = kvs->context;

    bd_size_t bd_size = MIN(context->device->size(context->device), 0x80000000L);

    memset(context->bank_params, 0, sizeof(context->bank_params));
    size_t bank0_size = 0;
    size_t bank1_size = 0;

    while (true) {
        bd_size_t erase_unit_size = ROUND_UP(bank0_size, context->device->erase_size);
        if (erase_unit_size == 0)
            erase_unit_size = context->device->erase_size;
        if (bank0_size + erase_unit_size <= (bd_size / 2)) {
            bank0_size += erase_unit_size;
        } else {
            break;
        }
    }

    while (true) {
        bd_size_t erase_unit_size = ROUND_UP(bank0_size + bank1_size, context->device->erase_size);
        if (erase_unit_size == 0)
            erase_unit_size = context->device->erase_size;
        if (bank1_size + erase_unit_size <= (bd_size / 2)) {
            bank1_size += erase_unit_size;
        } else {
            break;
        }
    }

    context->bank_params[0].address = 0;
    context->bank_params[0].size = bank0_size;
    context->bank_params[1].address = bank0_size;
    context->bank_params[1].size = bank1_size;
}

static int increment_max_keys(kvs_t *kvs, void **ram_index) {
    kvs_logkvs_context_t *context = kvs->context;

    ram_index_entry_t *old_ram_index = (ram_index_entry_t *)context->ram_index;
    ram_index_entry_t *new_ram_index = calloc(context->max_keys + 1, sizeof(ram_index_entry_t));
    memcpy(new_ram_index, old_ram_index, sizeof(ram_index_entry_t) * context->max_keys);
    context->max_keys++;

    context->ram_index = new_ram_index;
    free(old_ram_index);
    if (ram_index)
        *ram_index = context->ram_index;
    return KVSTORE_SUCCESS;
}

static int write_master_record(kvs_t *kvs, uint8_t bank, uint16_t version, uint32_t *next_offset) {
    kvs_logkvs_context_t *context = kvs->context;
    (void)bank;

    master_record_data_t master_rec = {.version = version};
    *next_offset = context->master_record_offset + context->master_record_size;
    return _set(kvs, master_rec_key, &master_rec, sizeof(master_rec), 0);
}

static void offset_in_erase_unit(kvs_t *kvs, uint8_t bank, uint32_t offset,
                                 uint32_t *offset_from_start, uint32_t *dist_to_end) {
    kvs_logkvs_context_t *context = kvs->context;

    uint32_t bd_offset = context->bank_params[bank].address + offset;
    uint32_t erase_unit = context->device->erase_size;
    *offset_from_start = bd_offset % erase_unit;
    *dist_to_end = erase_unit - *offset_from_start;
}

static int erase_bank(kvs_t *kvs, uint8_t bank, uint32_t offset, uint32_t size) {
    kvs_logkvs_context_t *context = kvs->context;

    uint32_t bd_offset = context->bank_params[bank].address + offset;
    int ret = context->device->erase(context->device, bd_offset, size);
    if (ret) {
        return ret;
    }

    return KVSTORE_SUCCESS;
}

static int read_bank(kvs_t *kvs, uint32_t bank, uint32_t offset, uint32_t size, void *buf) {
    kvs_logkvs_context_t *context = kvs->context;

    if (offset + size > context->size)
        return KVSTORE_ERROR_READ_FAILED;

    int rc = context->device->read(context->device, (const void *)buf,
                                   (bd_size_t)(context->bank_params[bank].address + offset),
                                   (bd_size_t)size);
    if (rc)
        return KVSTORE_ERROR_READ_FAILED;
    return KVSTORE_SUCCESS;
}

static int write_bank(kvs_t *kvs, uint8_t bank, uint32_t offset, uint32_t size, const void *buf) {
    kvs_logkvs_context_t *context = kvs->context;

    if (offset + size > context->size)
        return KVSTORE_ERROR_WRITE_FAILED;
    int ret = context->device->program(context->device, buf,
                                       context->bank_params[bank].address + offset, size);
    if (ret)
        return KVSTORE_ERROR_WRITE_FAILED;
    return KVSTORE_SUCCESS;
}

static int check_erase_before_write(kvs_t *kvs, uint8_t bank, uint32_t offset, uint32_t size,
                                    bool force_check) {
    bool erase = false;
    uint32_t start_offset;
    uint32_t end_offset;
    while (size) {
        uint32_t dist;
        uint32_t offset_from_start;
        offset_in_erase_unit(kvs, bank, offset, &offset_from_start, &dist);
        uint32_t chunk = MIN(size, dist);
        if (offset_from_start == 0 || force_check) {
            if (!erase) {
                erase = true;
                start_offset = offset - offset_from_start;
            }
            end_offset = offset + dist;
        }
        offset += chunk;
        size -= chunk;
    }

    if (erase) {
        int ret = erase_bank(kvs, bank, start_offset, end_offset - start_offset);
        if (ret != KVSTORE_SUCCESS)
            return KVSTORE_ERROR_WRITE_FAILED;
    }
    return KVSTORE_SUCCESS;
}

static int reset_bank(kvs_t *kvs, uint8_t bank) {
    kvs_logkvs_context_t *context = kvs->context;

    int ret;
    ret = check_erase_before_write(
        kvs, bank, 0,
        context->master_record_offset + context->master_record_size + context->device->program_size,
        true);
    return ret;
}

static int read_record(kvs_t *kvs, uint8_t bank, uint32_t offset, const char *key, void *data_buf,
                       uint32_t data_buf_size, uint32_t *actual_data_size, size_t data_offset,
                       bool copy_key, bool copy_data, bool check_expected_key, bool calc_hash,
                       uint32_t *hash, uint32_t *flags, uint32_t *next_offset) {
    kvs_logkvs_context_t *context = kvs->context;
    int ret;
    record_header_t header = {0};
    uint32_t total_size;
    uint32_t curr_data_offset;
    char *user_key_ptr;
    uint32_t crc = CRC32_ANSI_INIT;
    bool validate = (data_offset == 0);

    ret = KVSTORE_SUCCESS;
    *next_offset = offset;
    ret = read_bank(kvs, bank, offset, sizeof(header), &header);
    if (ret) {
        return ret;
    }
    if (header.magic != kvstore_magic) {
        return KVSTORE_ERROR_INVALID_DATA_DETECTED;
    }

    offset += align_up(sizeof(header), context->device->program_size);
    uint32_t key_size = header.key_size;
    uint32_t data_size = header.data_size;
    *flags = header.flags;

    if ((!key_size) || (key_size >= MAX_KEY_SIZE)) {
        printf("invalid 1\n");
        return KVSTORE_ERROR_INVALID_DATA_DETECTED;
    }

    total_size = key_size + data_size;

    if ((total_size < key_size) || (total_size < data_size)) {
        printf("invalid 2\n");
        return KVSTORE_ERROR_INVALID_DATA_DETECTED;
    }
    /* NOTE:
     * The Mbed OS implementation has `offset + total_size >= context->size`.
     * It has a problem that it considers a normal record that is just on the
     * edge of the boundary to be an error.
     */
    if (offset + total_size > context->size) {
        return KVSTORE_ERROR_INVALID_DATA_DETECTED;
    }
    if (data_offset > data_size) {
        return KVSTORE_ERROR_INVALID_SIZE;
    }

    *actual_data_size = MIN(data_buf_size, data_size - data_offset);

    if (copy_data && *actual_data_size && !data_buf) {
        return KVSTORE_ERROR_INVALID_ARGUMENT;
    }

    if (validate) {
        crc = calc_crc(crc, sizeof(record_header_t) - sizeof(crc), &header);
        curr_data_offset = 0;
    } else {
        total_size = *actual_data_size;
        curr_data_offset = data_offset;
        offset += data_offset + key_size;
        key_size = 0;
    }

    user_key_ptr = (char *)key;
    *hash = CRC32_ANSI_INIT;

    while (total_size) {
        uint8_t *dest_buf;
        uint32_t chunk_size;
        if (key_size) {
            if (copy_key) {
                dest_buf = (uint8_t *)user_key_ptr;
                chunk_size = key_size;
                user_key_ptr[key_size] = '\0';
            } else {
                dest_buf = context->work_buf;
                chunk_size = MIN(key_size, context->work_buf_size);
            }
        } else {
            if (curr_data_offset < data_offset) {
                chunk_size = MIN(context->work_buf_size, (data_offset - curr_data_offset));
                dest_buf = context->work_buf;
            } else if (copy_data && (curr_data_offset < data_offset + *actual_data_size)) {
                chunk_size = *actual_data_size;
                dest_buf = (uint8_t *)data_buf;
            } else {
                chunk_size = MIN(context->work_buf_size, total_size);
                dest_buf = context->work_buf;
            }
        }
        ret = read_bank(kvs, bank, offset, chunk_size, dest_buf);
        if (ret) {
            goto end;
        }

        if (validate) {
            crc = calc_crc(crc, chunk_size, dest_buf);
        }

        if (key_size) {
            if (check_expected_key) {
                if (memcmp(user_key_ptr, dest_buf, chunk_size)) {
                    ret = KVSTORE_ERROR_ITEM_NOT_FOUND;
                }
            }

            if (calc_hash) {
                *hash = calc_crc(*hash, chunk_size, dest_buf);
            }

            user_key_ptr += chunk_size;
            key_size -= chunk_size;
            if (!key_size) {
                offset += data_offset;
            }
        } else {
            curr_data_offset += chunk_size;
        }

        total_size -= chunk_size;
        offset += chunk_size;
    }

    if (validate && (crc != header.crc)) {
        printf("invalid 4\n");
        ret = KVSTORE_ERROR_INVALID_DATA_DETECTED;
        goto end;
    }

    *next_offset = (uint32_t)align_up(offset, context->device->program_size);

end:
    return ret;
}

static int find_record(kvs_t *kvs, uint8_t bank, const char *key, uint32_t *offset,
                       uint32_t *ram_index_ind, uint32_t *hash) {
    kvs_logkvs_context_t *context = kvs->context;
    (void)bank;

    ram_index_entry_t *ram_index = (ram_index_entry_t *)context->ram_index;
    ram_index_entry_t *entry;
    int ret = KVSTORE_ERROR_ITEM_NOT_FOUND;
    uint32_t actual_data_size;
    uint32_t flags;
    uint32_t unused_hash;
    uint32_t next_offset;

    *hash = calc_crc(CRC32_ANSI_INIT, strlen(key), key);
    for (*ram_index_ind = 0; *ram_index_ind < context->num_keys;
         *ram_index_ind = *ram_index_ind + 1) {
        (void)ram_index_ind;
        entry = &ram_index[*ram_index_ind];
        *offset = entry->bd_offset;
        if (*hash < entry->hash)
            continue;
        if (*hash > entry->hash)
            return KVSTORE_ERROR_ITEM_NOT_FOUND;
        ret = read_record(kvs, context->active_bank, *offset, key, 0, 0, &actual_data_size, 0,
                          false, false, true, false, &unused_hash, &flags, &next_offset);
        if (ret != KVSTORE_ERROR_ITEM_NOT_FOUND)
            break;
    }
    return ret;
}

static int copy_record(kvs_t *kvs, uint8_t from_bank, uint32_t from_offset, uint32_t to_offset,
                       uint32_t *to_next_offset) {
    kvs_logkvs_context_t *context = kvs->context;
    int ret;
    record_header_t header;
    uint32_t total_size;
    uint32_t chunk_size;

    ret = read_bank(kvs, from_bank, from_offset, sizeof(header), &header);
    if (ret)
        return ret;

    total_size = align_up(sizeof(record_header_t), context->device->program_size) +
                 align_up(header.key_size + header.data_size, context->device->program_size);
    if (to_offset + total_size > context->size)
        return KVSTORE_ERROR_MEDIA_FULL;
    ret = check_erase_before_write(kvs, 1 - from_bank, to_offset, total_size, false);
    if (ret)
        return ret;

    chunk_size = align_up(sizeof(record_header_t), context->device->program_size);
    memset(context->work_buf, 0, chunk_size);
    memcpy(context->work_buf, &header, sizeof(record_header_t));
    ret = write_bank(kvs, 1 - from_bank, to_offset, chunk_size, context->work_buf);
    if (ret)
        return ret;

    from_offset += chunk_size;
    to_offset += chunk_size;
    total_size -= chunk_size;

    while (total_size) {
        chunk_size = MIN(total_size, context->work_buf_size);
        ret = read_bank(kvs, from_bank, from_offset, chunk_size, context->work_buf);
        if (ret)
            return ret;
        ret = write_bank(kvs, 1 - from_bank, to_offset, chunk_size, context->work_buf);
        if (ret)
            return ret;

        from_offset += chunk_size;
        to_offset += chunk_size;
        total_size -= chunk_size;
    }
    *to_next_offset = align_up(to_offset, context->device->program_size);
    return KVSTORE_SUCCESS;
}

static int garbage_collection(kvs_t *kvs) {
    kvs_logkvs_context_t *context = kvs->context;

    ram_index_entry_t *ram_index = (ram_index_entry_t *)context->ram_index;
    uint32_t to_offset, to_next_offset;
    int ret;
    size_t ind;

    // Reset the standby bank
    ret = reset_bank(kvs, 1 - context->active_bank);
    if (ret)
        return ret;

    to_offset = context->master_record_offset + context->master_record_size;
    to_next_offset = to_offset;
    for (ind = 0; ind < context->num_keys; ind++) {
        uint32_t from_offset = ram_index[ind].bd_offset;
        ret = copy_record(kvs, context->active_bank, from_offset, to_offset, &to_next_offset);
        if (ret)
            return ret;

        // Update RAM index
        ram_index[ind].bd_offset = to_offset;
        to_offset = to_next_offset;
    }
    to_offset = to_next_offset;
    context->free_space_offset = to_next_offset;
    context->active_bank = 1 - context->active_bank;
    context->bank_version++;
    ret = write_master_record(kvs, context->active_bank, context->bank_version, &to_offset);
    if (ret)
        return ret;

    return KVSTORE_SUCCESS;
}

static int build_ram_index(kvs_t *kvs) {
    kvs_logkvs_context_t *context = kvs->context;

    ram_index_entry_t *ram_index = (ram_index_entry_t *)context->ram_index;
    uint32_t offset;
    uint32_t next_offset = 0;
    uint32_t dummy;
    int ret = KVSTORE_SUCCESS;
    uint32_t hash;
    uint32_t flags;
    uint32_t actual_data_size;
    uint32_t ram_index_ind;

    context->num_keys = 0;
    offset = context->master_record_offset;

    while (offset + sizeof(record_header_t) < context->free_space_offset) {
        ret = read_record(kvs, context->active_bank, offset, context->key_buf, 0, 0,
                          &actual_data_size, 0, true, false, false, true, &hash, &flags,
                          &next_offset);
        if (ret)
            goto end;

        ret =
            find_record(kvs, context->active_bank, context->key_buf, &dummy, &ram_index_ind, &hash);
        if ((ret != KVSTORE_SUCCESS) && (ret != KVSTORE_ERROR_ITEM_NOT_FOUND))
            goto end;

        uint32_t save_offset = offset;
        offset = next_offset;
        if (ret == KVSTORE_ERROR_ITEM_NOT_FOUND) {
            ret = KVSTORE_SUCCESS;
            if (flags & DELETE_FLAG)
                continue;
            if (context->num_keys >= context->max_keys) {
                increment_max_keys(kvs, (void **)&ram_index);
            }
            memmove(&ram_index[ram_index_ind + 1], &ram_index[ram_index_ind],
                    sizeof(ram_index_entry_t) * (context->num_keys - ram_index_ind));
            context->num_keys++;
        } else if (flags & DELETE_FLAG) {
            context->num_keys--;
            memmove(&ram_index[ram_index_ind], &ram_index[ram_index_ind + 1],
                    sizeof(ram_index_entry_t) * (context->num_keys - ram_index_ind));
            continue;
        }
        ram_index[ram_index_ind].hash = hash;
        ram_index[ram_index_ind].bd_offset = save_offset;
    }

end:
    context->free_space_offset = next_offset;
    return ret;
}

static void update_all_iterators(kvs_t *kvs, bool added, uint32_t ram_index_ind) {
    kvs_logkvs_context_t *context = kvs->context;

    for (int it_num = 0; it_num < MAX_OPEN_ITERATORS; it_num++) {
        kvs_find_t *handle = context->iterator_table[it_num];
        if (!handle) {
            continue;
        }

        if (ram_index_ind >= handle->ram_index_ind) {
            continue;
        }

        if (added) {
            handle->ram_index_ind++;
        } else {
            handle->ram_index_ind--;
        }
    }
}

static bool is_valid_key(const char *key) {
    if (key == NULL)
        return false;
    if (strlen(key) == 0)
        return false;
    if (strlen(key) > 128)
        return false;
    return true;
}

static int _set_start(kvs_t *kvs, kvs_inc_set_handle_t *handle, const char *key,
                      size_t final_data_size, uint32_t flags) {
    kvs_logkvs_context_t *context = kvs->context;

    int ret;
    uint32_t offset = 0;
    uint32_t hash = 0;
    uint32_t ram_index_ind = 0;
    inc_set_handle_t *ih;
    bool need_gc = false;

    if (!is_valid_key(key))
        return KVSTORE_ERROR_INVALID_ARGUMENT;

    if (flags & ~(supported_flags | internal_flags))
        return KVSTORE_ERROR_INVALID_ARGUMENT;

    handle->handle = context->inc_set_handle;
    ih = handle->handle;

    if (!strcmp(key, master_rec_key)) {
        ih->bd_base_offset = context->master_record_offset;
        ih->new_key = false;
        ram_index_ind = 0;
        hash = 0;
    } else {
        // mutex.lock()

        if (ih->header.magic == kvstore_magic) {
            ret = garbage_collection(kvs);
            if (ret)
                goto fail;
        }

        uint32_t rec_size = record_size(kvs, key, final_data_size);
        if (context->free_space_offset + rec_size > context->size) {
            ret = garbage_collection(kvs);
            if (ret)
                goto fail;
        }
        if (context->free_space_offset + rec_size > context->size) {
            ret = KVSTORE_ERROR_MEDIA_FULL;
            goto fail;
        }

        ret = find_record(kvs, context->active_bank, key, &offset, &ram_index_ind, &hash);
        if (ret == KVSTORE_SUCCESS) {
            ret = read_bank(kvs, context->active_bank, offset, sizeof(ih->header), &ih->header);
            if (ret)
                goto fail;
            if (ih->header.flags & KVSTORE_WRITE_ONCE_FLAG) {
                ret = KVSTORE_ERROR_WRITE_PROTECTED;
                goto fail;
            }
            ih->new_key = false;
        } else if (ret == KVSTORE_ERROR_ITEM_NOT_FOUND) {
            if (flags & DELETE_FLAG)
                goto fail;
            if (context->num_keys >= context->max_keys)
                increment_max_keys(kvs, NULL);
            ih->new_key = true;
        } else {
            goto fail;
        }
        ih->bd_base_offset = context->free_space_offset;

        check_erase_before_write(kvs, context->active_bank, ih->bd_base_offset, rec_size, false);
    }
    ret = KVSTORE_SUCCESS;

    ih->bd_curr_offset =
        ih->bd_base_offset + align_up(sizeof(record_header_t), context->device->program_size);
    ih->offset_in_data = 0;
    ih->hash = hash;
    ih->ram_index_ind = ram_index_ind;
    ih->header.magic = kvstore_magic;
    ih->header.header_size = sizeof(record_header_t);
    ih->header.flags = flags;
    ih->header.key_size = strlen(key);
    ih->header.data_size = final_data_size;
    ih->header.crc =
        calc_crc(CRC32_ANSI_INIT, sizeof(record_header_t) - sizeof(ih->header.crc), &ih->header);
    ih->header.crc = calc_crc(ih->header.crc, ih->header.key_size, key);

    ret = write_bank(kvs, context->active_bank, ih->bd_curr_offset, ih->header.key_size, key);
    if (ret) {
        need_gc = true;
        goto fail;
    }
    ih->bd_curr_offset += ih->header.key_size;
    goto end;

fail:
    if ((need_gc) && (ih->bd_base_offset != context->master_record_offset)) {
        garbage_collection(kvs);
    }
    ih->header.magic = 0;
    // mutex.unlock()

end:
    return ret;
}

static int _set_add_data(kvs_t *kvs, kvs_inc_set_handle_t *handle, const void *value_data,
                         size_t data_size) {
    kvs_logkvs_context_t *context = kvs->context;

    int ret = KVSTORE_SUCCESS;
    inc_set_handle_t *ih;
    bool need_gc = false;

    if (handle->handle != context->inc_set_handle)
        return KVSTORE_ERROR_INVALID_ARGUMENT;
    if (!value_data && data_size)
        return KVSTORE_ERROR_INVALID_ARGUMENT;

    // inc_set_mutex.lock()
    ih = handle->handle;
    if (!ih->header.magic) {
        ret = KVSTORE_ERROR_INVALID_ARGUMENT;
        goto end;
    }
    if (ih->offset_in_data + data_size > ih->header.data_size) {
        ret = KVSTORE_ERROR_INVALID_SIZE;
        goto end;
    }
    ih->header.crc = calc_crc(ih->header.crc, data_size, value_data);
    ret = write_bank(kvs, context->active_bank, ih->bd_curr_offset, data_size, value_data);
    if (ret) {
        need_gc = true;
        goto end;
    }
    ih->bd_curr_offset += data_size;
    ih->offset_in_data += data_size;

end:
    if ((need_gc) && (ih->bd_base_offset != context->master_record_offset))
        garbage_collection(kvs);
    // inc_set_mutex.unlock();
    return ret;
}

static int _set_finalize(kvs_t *kvs, kvs_inc_set_handle_t *handle) {
    kvs_logkvs_context_t *context = kvs->context;
    int os_ret;
    int ret = KVSTORE_SUCCESS;
    inc_set_handle_t *ih;
    ram_index_entry_t *ram_index = (ram_index_entry_t *)context->ram_index;
    ram_index_entry_t *entry;
    bool need_gc = false;
    uint32_t actual_data_size, hash, flags, next_offset;

    if (handle->handle != context->inc_set_handle)
        return KVSTORE_ERROR_INVALID_ARGUMENT;
    ih = handle->handle;
    if (!ih->header.magic)
        return KVSTORE_ERROR_INVALID_ARGUMENT;

    // inc_set_mutex.lock()
    if (ih->offset_in_data != ih->header.data_size) {
        ret = KVSTORE_ERROR_INVALID_SIZE;
        need_gc = true;
        goto end;
    }

    ret = write_bank(kvs, context->active_bank, ih->bd_base_offset, sizeof(record_header_t),
                     &ih->header);
    if (ret) {
        need_gc = true;
        goto end;
    }

    os_ret = context->device->sync(context->device);
    if (os_ret) {
        ret = KVSTORE_ERROR_WRITE_FAILED;
        need_gc = true;
        goto end;
    }

    if (ih->bd_base_offset == context->master_record_offset)
        goto end;

    ret =
        read_record(kvs, context->active_bank, ih->bd_base_offset, 0, 0, (uint32_t)-1,
                    &actual_data_size, 0, false, false, false, false, &hash, &flags, &next_offset);
    if (ret) {
        need_gc = true;
        goto end;
    }

    // Update RAM table
    if (ih->header.flags & DELETE_FLAG) {
        context->num_keys--;
        if (ih->ram_index_ind < context->num_keys) {
            memmove(&ram_index[ih->ram_index_ind], &ram_index[ih->ram_index_ind + 1],
                    sizeof(ram_index_entry_t) * (context->num_keys - ih->ram_index_ind));
        }
        update_all_iterators(kvs, false, ih->ram_index_ind);
    } else {
        if (ih->new_key) {
            if (ih->ram_index_ind < context->num_keys) {
                memmove(&ram_index[ih->ram_index_ind + 1], &ram_index[ih->ram_index_ind],
                        sizeof(ram_index_entry_t) * (context->num_keys - ih->ram_index_ind));
            }
            context->num_keys++;
            update_all_iterators(kvs, true, ih->ram_index_ind);
        }
        entry = &ram_index[ih->ram_index_ind];
        entry->hash = ih->hash;
        entry->bd_offset = ih->bd_base_offset;
    }

    context->free_space_offset = align_up(ih->bd_curr_offset, context->device->program_size);

    os_ret =
        read_record(kvs, context->active_bank, context->free_space_offset, 0, 0, 0,
                    &actual_data_size, 0, false, false, false, false, &hash, &flags, &next_offset);
    if (os_ret == KVSTORE_SUCCESS)
        check_erase_before_write(kvs, context->active_bank, context->free_space_offset,
                                 sizeof(record_header_t), false);

end:
    ih->header.magic = 0;
    // _inc_set_mutex.unlock();

    if (ih->bd_base_offset != context->master_record_offset) {
        if (need_gc)
            garbage_collection(kvs);
        // _mutex.unlock();
    }
    return ret;
}

static int _set(kvs_t *kvs, const char *key, const void *buffer, size_t size, uint32_t flags) {
    int ret;
    kvs_inc_set_handle_t handle;
    if (!buffer && size) {
        return KVSTORE_ERROR_INVALID_ARGUMENT;
    }
    ret = _set_start(kvs, &handle, key, size, flags);
    if (ret) {
        return ret;
    }
    ret = _set_add_data(kvs, &handle, buffer, size);
    if (ret) {
        return ret;
    }
    ret = _set_finalize(kvs, &handle);
    return ret;
}

static int _get(kvs_t *kvs, const char *key, void *buffer, size_t buffer_size, size_t *actual_size,
                size_t offset) {
    kvs_logkvs_context_t *context = kvs->context;
    int ret;
    uint32_t actual_data_size = 0;
    uint32_t bd_offset, next_bd_offset;
    uint32_t flags, hash, ram_index_ind;

    // is_valid_key

    // mutex.lock()

    ret = find_record(kvs, context->active_bank, key, &bd_offset, &ram_index_ind, &hash);
    if (ret != KVSTORE_SUCCESS)
        goto end;

    ret = read_record(kvs, context->active_bank, bd_offset, key, buffer, buffer_size,
                      &actual_data_size, offset, false, true, false, false, &hash, &flags,
                      &next_bd_offset);
    if (actual_size)
        *actual_size = actual_data_size;

end:
    // mutex.unlock()
    return ret;
}

static int _get_info(struct kvstore *kvs, const char *key, kvs_info_t *info) {
    int ret;
    uint32_t bd_offset;
    uint32_t actual_data_size;
    uint32_t hash;
    uint32_t flags;
    uint32_t next_bd_offset;
    uint32_t ram_index_ind;

    kvs_logkvs_context_t *context = kvs->context;

    // mutex.lock();

    ret = find_record(kvs, context->active_bank, key, &bd_offset, &ram_index_ind, &hash);
    if (ret)
        goto end;

    ret = read_record(kvs, context->active_bank, bd_offset, key, 0, (uint32_t)-1, &actual_data_size,
                      0, false, false, false, false, &hash, &flags, &next_bd_offset);
    if (ret)
        goto end;

    if (info) {
        info->flags = flags;
        info->size = actual_data_size;
    }

end:
    // mutex.unlock();
    return ret;
}

static int _delete(kvs_t *kvs, const char *key) { return _set(kvs, key, 0, 0, DELETE_FLAG); }

static int _find(kvs_t *kvs, const char *prefix, kvs_find_t *find_ctx) {
    kvs_logkvs_context_t *context = kvs->context;
    int ret = KVSTORE_SUCCESS;

    // mutex.lock()
    int it_num;
    for (it_num = 0; it_num < MAX_OPEN_ITERATORS; it_num++) {
        if (!context->iterator_table[it_num])
            break;
    }
    if (it_num == MAX_OPEN_ITERATORS) {
        ret = KVSTORE_ERROR_OUT_OF_RESOURCES;
        goto end;
    }

    if (prefix && strcmp(prefix, "") != 0) {
        find_ctx->prefix = prefix;
    } else {
        find_ctx->prefix = NULL;
    }
    find_ctx->ram_index_ind = 0;
    find_ctx->iterator_num = it_num;
    context->iterator_table[it_num] = find_ctx;

end:
    // mutex.unlock()
    return ret;
}

static int _find_next(kvs_t *kvs, kvs_find_t *find_ctx, const char *key, size_t key_size) {
    kvs_logkvs_context_t *context = kvs->context;
    ram_index_entry_t *ram_index = (ram_index_entry_t *)context->ram_index;
    int ret = KVSTORE_ERROR_ITEM_NOT_FOUND;
    uint32_t actual_data_size, hash, flags, next_offset;

    // mutex.lock()
    while (ret && (find_ctx->ram_index_ind < context->num_keys)) {
        ret = read_record(kvs, context->active_bank, ram_index[find_ctx->ram_index_ind].bd_offset,
                          context->key_buf, 0, 0, &actual_data_size, 0, true, false, false, false,
                          &hash, &flags, &next_offset);
        if (ret)
            goto end;
        if (!find_ctx->prefix || (strstr(context->key_buf, find_ctx->prefix) == context->key_buf)) {
            if (strlen(context->key_buf) >= key_size) {
                ret = KVSTORE_ERROR_INVALID_SIZE;
                goto end;
            }
            strcpy((char *)key, context->key_buf);
        } else {
            ret = KVSTORE_ERROR_ITEM_NOT_FOUND;
        }
        find_ctx->ram_index_ind++;
    }
end:
    // mutex.unlock()
    return ret;
}

static int _find_close(kvs_t *kvs, kvs_find_t *find_ctx) {
    kvs_logkvs_context_t *context = kvs->context;

    // mutex.lock()
    context->iterator_table[find_ctx->iterator_num] = NULL;

    // mutex.unlock();
    return KVSTORE_SUCCESS;
}

kvs_t *kvs_logkvs_create(blockdevice_t *bd) {
    uint32_t actual_data_size;
    int ret = KVSTORE_SUCCESS;
    uint32_t flags;
    uint32_t hash;
    master_record_data_t master_rec;
    uint32_t next_offset;

    kvs_t *kvs = calloc(1, sizeof(kvs_t));
    if (kvs == NULL) {
        fprintf(stderr, "kvs_create: Out of memory\n");
        return NULL;
    }

    kvs_logkvs_context_t *context = calloc(1, sizeof(kvs_logkvs_context_t));
    kvs->context = context;
    kvs->handle_size = sizeof(inc_set_handle_t);

    context->ram_index = calloc(KVSTORE_NUM_BANK, sizeof(ram_index_entry_t));
    if (context->ram_index == NULL) {
        fprintf(stderr, "kvs_create: Out of memory\n");
        free(kvs->context);
        free(kvs);
        return NULL;
    }
    context->work_buf_size = MAX(bd->program_size, MIN_WORK_BUF_SIZE);
    context->work_buf = calloc(1, context->work_buf_size);
    if (context->work_buf == NULL) {
        fprintf(stderr, "kvs_create: Out of memory\n");
        free(context->ram_index);
        free(kvs->context);
        free(kvs);
        return NULL;
    }
    context->key_buf = calloc(1, MAX_KEY_SIZE);
    if (context->key_buf == NULL) {
        fprintf(stderr, "kvs_create: Out of memory\n");
        free(context->work_buf);
        free(context->ram_index);
        free(kvs->context);
        free(kvs);
        return NULL;
    }
    context->inc_set_handle = calloc(1, sizeof(inc_set_handle_t));
    if (context->inc_set_handle == NULL) {
        fprintf(stderr, "kvs_create: Out of memory\n");
        free(context->key_buf);
        free(context->work_buf);
        free(context->ram_index);
        free(kvs->context);
        free(kvs);
        return NULL;
    }

    kvs->set = _set;
    kvs->get = _get;
    kvs->delete = _delete;
    kvs->find = _find;
    kvs->find_next = _find_next;
    kvs->find_close = _find_close;
    kvs->set_start = _set_start;
    kvs->set_add_data = _set_add_data;
    kvs->set_finalize = _set_finalize;
    kvs->get_info = _get_info;

    context->num_keys = 0;
    context->device = blockdevice_stage_create(bd);
    if (context->device == NULL)
        goto fail;

    context->master_record_offset = align_up(0, bd->program_size);
    context->master_record_size = record_size(kvs, master_rec_key, sizeof(master_record_data_t));

    update_bank_params(kvs);
    bank_state_t bank_state[KVSTORE_NUM_BANK];

    size_t _size = (size_t)-1;
    for (uint8_t bank = 0; bank < KVSTORE_NUM_BANK; bank++) {
        bank_state[bank] = KVSTORE_BANK_STATE_NONE;

        context->size = MIN(_size, context->bank_params[bank].size);

        ret = read_record(kvs, bank, context->master_record_offset, master_rec_key, &master_rec,
                          sizeof(master_rec), &actual_data_size, 0, false, true, true, false, &hash,
                          &flags, &next_offset);
        if ((ret != KVSTORE_SUCCESS) && (ret != KVSTORE_ERROR_INVALID_DATA_DETECTED)) {
            printf("KVSTORE: Unable to read record at init\n");
        }

        if (ret == KVSTORE_ERROR_INVALID_DATA_DETECTED) {
            bank_state[bank] = KVSTORE_BANK_STATE_INVALID;
            continue;
        }

        bank_state[bank] = KVSTORE_BANK_STATE_VALID;

        context->active_bank = bank;
    }
    if ((bank_state[0] == KVSTORE_BANK_STATE_INVALID) &&
        (bank_state[1] == KVSTORE_BANK_STATE_INVALID)) {
        reset_bank(kvs, 0);
        context->active_bank = 0;
        context->bank_version = 1;
        bank_state[0] = KVSTORE_BANK_STATE_ERASED;

        ret = write_master_record(kvs, context->active_bank, context->bank_version,
                                  &context->free_space_offset);
        if (ret) {
            printf("KVSTORE: Unable to write master rcord at init ret=%d\n", ret);
        }
        goto end;
    }

    if ((bank_state[0] == KVSTORE_BANK_STATE_VALID) &&
        (bank_state[1] == KVSTORE_BANK_STATE_VALID)) {
        ;  //
    }

    context->free_space_offset = _size;
    ret = build_ram_index(kvs);
    if ((ret != KVSTORE_SUCCESS) && (ret != KVSTORE_ERROR_INVALID_DATA_DETECTED)) {
        goto fail;
    }

end:
    kvs->is_initialized = true;
    return kvs;

fail:
    free(context->work_buf);
    free(context->key_buf);
    free(context->inc_set_handle);
    free(context->ram_index);
    free(kvs->context);
    free(kvs);

    return NULL;
}

void kvs_logkvs_free(kvs_t *kvs) {
    kvs_logkvs_context_t *context = kvs->context;

    free(context->work_buf);
    free(context->key_buf);
    free(context->inc_set_handle);
    free(context->ram_index);
    free(kvs->context);
    free(kvs);
}
