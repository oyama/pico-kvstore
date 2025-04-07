/*
 * Copyright 2025, Hiroyuki OYAMA
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */
#pragma once

#include <stdint.h>
#include <stddef.h>

#define CRC32_ANSI_INIT  0xFFFFFFFFU
#define CRC32_ANSI_FINAL 0xFFFFFFFFU

// CRC-32 ANSI
uint32_t crc32_ansi(const uint8_t *data, size_t length);
uint32_t crc32_ansi_update_block(uint32_t crc, const void *data, size_t length);
uint32_t crc32_ansi_update_final(uint32_t crc);
