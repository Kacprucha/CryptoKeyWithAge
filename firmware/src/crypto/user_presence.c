#include "user_presence.h"
#include "pico/stdlib.h"
#include "hardware/gpio.h"
#include <string.h>
#include <stdint.h>

static volatile bool s_tup_pending   = false;
static volatile bool s_button_pressed = false;
static volatile uint32_t s_last_press_ms = 0;
static uint32_t s_request_ms   = 0;

volatile bool s_tup_pending_for_ecdh   = false;
volatile bool s_tup_pending_for_pubkey = false;

/* --- LED blink state --- */
static bool s_led_state = false;

static void gpio_button_callback(uint gpio, uint32_t events) 
{
    if (gpio != BUTTON_PIN) return;

    if (!(events & GPIO_IRQ_EDGE_FALL))
    { 
        return;
    }

    uint32_t now = to_ms_since_boot(get_absolute_time());

    if ((now - s_last_press_ms) < DEBOUNCE_MS) 
    {
        return;
    }

    s_last_press_ms = now;

    if (s_tup_pending) 
    {
        s_button_pressed = true;
    }
}

void tup_init(void) 
{
    gpio_init(BUTTON_PIN);
    gpio_set_dir(BUTTON_PIN, GPIO_IN);
    gpio_pull_up(BUTTON_PIN);

    gpio_init(LED_PIN);
    gpio_set_dir(LED_PIN, GPIO_OUT);
    gpio_put(LED_PIN, 0);


    gpio_set_irq_enabled_with_callback(BUTTON_PIN, GPIO_IRQ_EDGE_FALL, true, gpio_button_callback);
}

void tup_request(void) 
{
    s_button_pressed = false;
    s_tup_pending = true;
    s_request_ms = to_ms_since_boot(get_absolute_time());

    gpio_put(LED_PIN, 1);
}

bool tup_check(void) 
{
    if (!s_tup_pending)  
    {
        return false;
    }

    if (tup_timed_out()) 
    {
        tup_cancel();
        return false;
    }

    if (s_button_pressed) 
    {
        s_button_pressed = false;
        s_tup_pending = false;
        gpio_put(LED_PIN, 0);
        return true;
    }

    return false;
}

void tup_cancel(void) 
{
    s_tup_pending    = false;
    s_button_pressed = false;
    gpio_put(LED_PIN, 0);
}

bool tup_timed_out(void) 
{
    if (!s_tup_pending) return false;
    uint32_t elapsed = to_ms_since_boot(get_absolute_time()) - s_request_ms;
    return elapsed >= TUP_TIMEOUT_MS;
}