#include <stdio.h>
#include <pico/stdlib.h>

#define COLOR_GREEN(format)  ("\e[32m" format "\e[0m")

extern void test_global_kvs(void);
extern void test_global_kvs_secure(void);

int main(void) {
    stdio_init_all();

    printf("Start all tests\n");

    test_global_kvs();
    test_global_kvs_secure();

    printf(COLOR_GREEN("All tests are ok\n"));
    while (1)
        tight_loop_contents();
}
