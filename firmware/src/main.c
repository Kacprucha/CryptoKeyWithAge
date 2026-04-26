#include <stdio.h>
#include "pico/stdlib.h"
#include "hardware/i2c.h"
#include "hardware/watchdog.h"
#include "tusb.h"
#include "cryptoauthlib.h"
#include "user_presence.h"

// Pico W devices use a GPIO on the WIFI chip for the LED,
// so when building for Pico W, CYW43_WL_GPIO_LED_PIN will be defined
#ifdef CYW43_WL_GPIO_LED_PIN
#include "pico/cyw43_arch.h"
#endif

// Perform initialisation
int pico_led_init(void) {
#if defined(PICO_DEFAULT_LED_PIN)
    // A device like Pico that uses a GPIO for the LED will define PICO_DEFAULT_LED_PIN
    // so we can use normal GPIO functionality to turn the led on and off
    gpio_init(PICO_DEFAULT_LED_PIN);
    gpio_set_dir(PICO_DEFAULT_LED_PIN, GPIO_OUT);
    return PICO_OK;
#elif defined(CYW43_WL_GPIO_LED_PIN)
    // For Pico W devices we need to initialise the driver etc
    return cyw43_arch_init();
#endif
}

// Turn the led on or off
void pico_set_led(bool led_on) {
#if defined(PICO_DEFAULT_LED_PIN)
    // Just set the GPIO on or off
    gpio_put(PICO_DEFAULT_LED_PIN, led_on);
#elif defined(CYW43_WL_GPIO_LED_PIN)
    // Ask the wifi "driver" to set the GPIO on or off
    cyw43_arch_gpio_put(CYW43_WL_GPIO_LED_PIN, led_on);
#endif
}

int main() 
{
    int rc = pico_led_init();
    hard_assert(rc == PICO_OK);

    stdio_init_all();
    tusb_init(BOARD_TUD_RHPORT, BOARD_TUD_MAX_SPEED);

    // Inicialization I2C 
    i2c_init(i2c0, 100 * 1000);  // form test it needs to be 100kHz
    gpio_set_function(4, GPIO_FUNC_I2C);
    gpio_set_function(5, GPIO_FUNC_I2C);
    gpio_pull_up(4);
    gpio_pull_up(5);
    sleep_ms(100);
    
    ATCAIfaceCfg atecc608_cfg = cfg_ateccx08a_i2c_default;
    atecc608_cfg.atcai2c.address = 0xC0;
    atecc608_cfg.atcai2c.baud = 100000;
    atecc608_cfg.iface_type = ATCA_I2C_IFACE;
    atecc608_cfg.devtype = ATECC608A;

    ATCA_STATUS status = atcab_init(&atecc608_cfg);
    if (status != ATCA_SUCCESS) 
    {
        pico_set_led(true); // Turn on LED to indicate error
    }

    tup_init();

    while (true) 
    {
        tud_task(); // tinyusb device task
        watchdog_update();

        if (tup_timed_out()) 
        {
            tup_cancel();
            s_tup_pending_for_ecdh   = false;
            s_tup_pending_for_pubkey = false;
        }
    }

    return 0;
}