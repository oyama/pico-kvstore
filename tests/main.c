#include <stdio.h>
#include <pico/stdlib.h>

#define COLOR_GREEN(format)  ("\e[32m" format "\e[0m")

extern void test_kvstore_logkvs(void);
extern void test_kvstore_securekvs(void);
extern void test_fault(void);
#if PICO_ON_DEVICE

#endif


#ifdef CYW43_WL_GPIO_LED_PIN
#include "pico/cyw43_arch.h"
#endif

static void led_turn_on(void) {
//#if PICO_ON_DEVICE

#if defined(PICO_DEFAULT_LED_PIN)
    gpio_init(PICO_DEFAULT_LED_PIN);
    gpio_set_dir(PICO_DEFAULT_LED_PIN, GPIO_OUT);
    gpio_put(PICO_DEFAULT_LED_PIN, true);
#endif

#if defined(CYW43_WL_GPIO_LED_PIN)
    cyw43_arch_init();
    cyw43_arch_gpio_put(CYW43_WL_GPIO_LED_PIN, true);
#endif

//#endif
}

int main(void) {
    stdio_init_all();

    printf("Start all tests\n");

    test_kvstore_logkvs();
    test_kvstore_securekvs();
    test_fault();
#if PICO_ON_DEVICE

#endif

    printf(COLOR_GREEN("All tests are ok\n"));

    led_turn_on();
#if PICO_ON_DEVICE
    while (1)
        tight_loop_contents();
#endif
    return 0;
}
