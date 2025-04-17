/*
 * Copyright 2025, Hiroyuki OYAMA
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "blockdevice/blockdevice.h"
#include "blockdevice_fault.h"

static const char DEVICE_NAME[] = "fault";

static int init(blockdevice_t *device) {
    blockdevice_fault_config_t *config = device->config;

    if (device->is_initialized) {
        return BD_ERROR_OK;
    }

    config->program_count = 0;
    config->fault_from = 0;
    device->is_initialized = true;

    return BD_ERROR_OK;
}

static int deinit(blockdevice_t *device) {
    blockdevice_fault_config_t *config = device->config;

    if (!device->is_initialized) {
        return BD_ERROR_OK;
    }

    int rc = config->underlying->deinit(config->underlying);
    if (rc != BD_ERROR_OK) {
        return rc;
    }

    device->is_initialized = false;

    return BD_ERROR_OK;
}

static int sync(blockdevice_t *device) {
    blockdevice_fault_config_t *config = device->config;
    return config->underlying->sync(config->underlying);
}

static int read(blockdevice_t *device, const void *buffer, bd_size_t addr, bd_size_t length) {
    blockdevice_fault_config_t *config = device->config;
    return config->underlying->read(config->underlying, buffer, addr, length);
}

static int erase(blockdevice_t *device, bd_size_t addr, bd_size_t length) {
    blockdevice_fault_config_t *config = device->config;
    return config->underlying->erase(config->underlying, addr, length);
}

static int program(blockdevice_t *device, const void *buffer, bd_size_t addr, bd_size_t length) {
    blockdevice_fault_config_t *config = device->config;

    int ret = BD_ERROR_OK;

    config->program_count++;
    if (config->fault_from > 0 && config->fault_from <= config->program_count)
        ret = BD_ERROR_DEVICE_ERROR;
    else
        ret = config->underlying->program(config->underlying, buffer, addr, length);

    return ret;
}

static int trim(blockdevice_t *device, bd_size_t addr, bd_size_t length) {
    blockdevice_fault_config_t *config = device->config;
    return config->underlying->trim(config->underlying, addr, length);
}

static bd_size_t size(blockdevice_t *device) {
    blockdevice_fault_config_t *config = device->config;
    return config->underlying->size(config->underlying);
}

blockdevice_t *blockdevice_fault_create(blockdevice_t *underlying) {
    blockdevice_t *device = calloc(1, sizeof(blockdevice_t));
    if (device == NULL) {
        return NULL;
    }
    blockdevice_fault_config_t *config = calloc(1, sizeof(blockdevice_fault_config_t));
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
    device->read_size = underlying->read_size;
    device->erase_size = underlying->erase_size;
    device->program_size = underlying->program_size;
    device->name = DEVICE_NAME;
    device->is_initialized = false;

    config->size = underlying->size(underlying);
    config->underlying = underlying;

    device->config = config;
    device->init(device);
    return device;
}

void blockdevice_fault_free(blockdevice_t *device) {
    device->deinit(device);
    free(device->config);
    free(device);
}

uint32_t blockdevice_fault_program_count(blockdevice_t *device) {
    blockdevice_fault_config_t *config = device->config;
    return config->program_count;
}

void blockdevice_fault_set_fault_from(blockdevice_t *device, uint32_t program_count) {
    blockdevice_fault_config_t *config = device->config;
    config->fault_from = program_count;
}

