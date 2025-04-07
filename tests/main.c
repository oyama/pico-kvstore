#include <stdio.h>
#include <pico/stdlib.h>

#define COLOR_GREEN(format)  ("\e[32m" format "\e[0m")

extern void test_kvstore_logkvs(void);
extern void test_kvstore_securekvs(void);

int main(void) {
    stdio_init_all();

    printf("Start all tests\n");

    test_kvstore_logkvs();
    test_kvstore_securekvs();

    printf(COLOR_GREEN("All tests are ok\n"));
    while (1)
        tight_loop_contents();
}
