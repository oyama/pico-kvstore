/*
 * Copyright 2025, Hiroyuki OYAMA
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "blockdevice_stage.h"

#include <stdio.h>
#include <string.h>

#include "pico/mutex.h"

typedef struct {
    blockdevice_t *bd;
    size_t size;
    bd_size_t write_cache_addr;
    bool write_cache_valid;
    uint8_t *write_cache;
    uint8_t *read_buf;
    bool is_initialized;
    mutex_t _mutex;
} blockdevice_stage_config_t;

static const char DEVICE_NAME[] = "stage";

static inline uint32_t align_down(bd_size_t val, bd_size_t size) { return val / size * size; }

static void invalidate_write_cache(blockdevice_t *device) {
    blockdevice_stage_config_t *config = device->config;
    config->write_cache_addr = device->size(device);
    config->write_cache_valid = false;
}

static int flush(blockdevice_t *device) {
    blockdevice_stage_config_t *config = device->config;
    if (!config->is_initialized)
        return BD_ERROR_DEVICE_ERROR;

    if (config->write_cache_valid) {
        int ret = config->bd->program(config->bd, config->write_cache, config->write_cache_addr,
                                      config->bd->program_size);
        if (ret)
            return ret;
        invalidate_write_cache(device);
    }
    return 0;
}

static int init(blockdevice_t *device) {
    blockdevice_stage_config_t *config = device->config;

    int err = config->bd->init(config->bd);
    if (err)
        return err;

    config->write_cache = calloc(1, config->bd->program_size);
    config->read_buf = calloc(1, config->bd->program_size);

    invalidate_write_cache(device);
    config->is_initialized = true;
    return BD_ERROR_OK;
}

static int deinit(blockdevice_t *device) {
    blockdevice_stage_config_t *config = device->config;
    if (!config->is_initialized)
        return BD_ERROR_OK;

    int err = device->sync(device);
    if (err)
        return err;

    free(config->write_cache);
    config->write_cache = NULL;
    free(config->read_buf);
    config->read_buf = NULL;
    config->is_initialized = false;
    return config->bd->deinit(config->bd);
}

static int read(blockdevice_t *device, const void *buffer, bd_size_t addr, bd_size_t length) {
    blockdevice_stage_config_t *config = device->config;
    if (!config->is_initialized)
        return BD_ERROR_DEVICE_ERROR;

    // Common case - no need to involve write cache or read buffer
    if ((addr + length <= config->write_cache_addr) ||
        (addr > config->write_cache_addr + config->bd->program_size)) {
        return config->bd->read(config->bd, buffer, addr, length);
    }

    // Read logic: Split read to chunks, according to whether we cross the write cache
    while (length) {
        bd_size_t chunk;
        bool read_from_bd = true;
        if (config->write_cache_valid && addr < config->write_cache_addr) {
            chunk = MIN(length, config->write_cache_addr - addr);
        } else if (config->write_cache_valid && (addr >= config->write_cache_valid) &&
                   (addr < config->write_cache_addr + config->bd->program_size)) {
            // One case we need to take our data from cache
            chunk = MIN(length, config->bd->program_size - addr % config->bd->program_size);
            memcpy((void *)buffer,
                   (const void *)config->write_cache + addr % config->bd->program_size, chunk);
            read_from_bd = false;
        } else {
            chunk = length;
        }

        // Now, in case we read from the BD, make shure we are aligned with its read size.
        // It not, use read buffer as a helper.
        if (read_from_bd) {
            bd_size_t offs_in_read_buf = addr % config->bd->read_size;
            int ret;
            if (offs_in_read_buf || (chunk < config->bd->read_size)) {
                chunk = MIN(chunk, config->bd->read_size - offs_in_read_buf);
                ret = config->bd->read(config->bd, config->read_buf, addr - offs_in_read_buf,
                                       config->bd->read_size);
                memcpy((void *)buffer, (const void *)config->read_buf + offs_in_read_buf, chunk);
            } else {
                chunk = align_down(chunk, config->bd->read_size);
                ret = config->bd->read(config->bd, buffer, addr, chunk);
            }
            if (ret)
                return ret;
        }

        buffer += chunk;
        addr += chunk;
        length -= chunk;
    }
    return 0;
}

static int erase(blockdevice_t *device, bd_size_t addr, bd_size_t size) {
    blockdevice_stage_config_t *config = device->config;
    if (!config->is_initialized)
        return BD_ERROR_DEVICE_ERROR;

    if ((config->write_cache_addr >= addr) && (config->write_cache_addr <= addr + size))
        invalidate_write_cache(device);
    return config->bd->erase(config->bd, addr, size);
}

static int program(blockdevice_t *device, const void *buffer, bd_size_t addr, bd_size_t length) {
    blockdevice_stage_config_t *config = device->config;
    if (!config->is_initialized)
        return BD_ERROR_DEVICE_ERROR;

    int ret;
    bd_size_t aligned_addr = align_down(addr, config->bd->program_size);
    // Need to flush if moved to another program unit
    if (aligned_addr != config->write_cache_addr) {
        ret = flush(device);
        if (ret)
            return ret;
    }

    // Write logic: Keep data in cache as long as we don't reach the end of the program unit.
    // Otherwise, program to the underlying BD.
    while (length) {
        config->write_cache_addr = align_down(addr, config->bd->program_size);
        bd_size_t offs_in_buf = addr - config->write_cache_addr;
        bd_size_t chunk;
        if (offs_in_buf) {
            chunk = MIN(config->bd->program_size - offs_in_buf, length);
        } else if (length >= config->bd->program_size) {
            chunk = align_down(length, config->bd->program_size);
        } else {
            chunk = length;
        }

        const uint8_t *prog_buf;
        if (chunk < config->bd->program_size) {
            // If cache not valid, and program doesn't cover an entire unit, it means we need to
            // read it from the underlying BD.
            if (!config->write_cache_valid) {
                ret = config->bd->read(config->bd, config->write_cache, config->write_cache_addr,
                                       config->bd->program_size);
                if (ret)
                    return ret;
            }
            memcpy(config->write_cache + offs_in_buf, buffer, chunk);
            prog_buf = config->write_cache;
        } else {
            prog_buf = buffer;
        }

        // Only program if we reached the end of a program unit
        if (!((offs_in_buf + chunk) % config->bd->program_size)) {
            ret = config->bd->program(config->bd, prog_buf, config->write_cache_addr,
                                      MAX(chunk, config->bd->program_size));
            if (ret)
                return ret;
            invalidate_write_cache(device);
            ret = config->bd->sync(config->bd);
            if (ret)
                return ret;
        } else {
            config->write_cache_valid = true;
        }

        buffer += chunk;
        addr += chunk;
        length -= chunk;
    }
    return 0;
}

static int trim(blockdevice_t *device, bd_size_t addr, bd_size_t length) {
    blockdevice_stage_config_t *config = device->config;
    if (!config->is_initialized)
        return BD_ERROR_DEVICE_ERROR;

    if ((config->write_cache_addr >= addr) && (config->write_cache_addr <= addr + length))
        invalidate_write_cache(device);
    return config->bd->trim(config->bd, addr, length);
}

static int sync(blockdevice_t *device) {
    blockdevice_stage_config_t *config = device->config;
    if (!config->is_initialized)
        return BD_ERROR_DEVICE_ERROR;

    int ret = flush(device);
    if (ret)
        return ret;
    return config->bd->sync(config->bd);
}

static bd_size_t size(blockdevice_t *device) {
    blockdevice_stage_config_t *config = device->config;
    return config->bd->size(config->bd);
}

blockdevice_t *blockdevice_stage_create(blockdevice_t *bd) {
    blockdevice_t *device = calloc(1, sizeof(blockdevice_t));
    if (device == NULL) {
        return NULL;
    }
    blockdevice_stage_config_t *config = calloc(1, sizeof(blockdevice_stage_config_t));
    if (config == NULL) {
        free(device);
        return NULL;
    }

    device->init = init;
    device->deinit = deinit;
    device->read = read;
    device->erase = erase;
    device->program = program;
    device->trim = trim;
    device->sync = sync;
    device->size = size;
    device->read_size = 1;
    device->erase_size = bd->erase_size;
    device->program_size = 1;
    device->name = DEVICE_NAME;
    device->is_initialized = false;

    config->bd = bd;
    mutex_init(&config->_mutex);
    device->config = config;
    device->init(device);
    return device;
}

void blockdevice_stage_free(blockdevice_t *device) {
    device->deinit(device);
    free(device->config);
    free(device);
}
