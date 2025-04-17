#pragma once

#define COLOR_GREEN(format)  ("\e[32m" format "\e[0m")


void test_printf(const char *format, ...);

blockdevice_t *blockdevice_test_create(void);

void blockdevice_test_free(blockdevice_t *bd);
