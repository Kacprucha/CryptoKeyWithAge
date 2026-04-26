#pragma once
#include <stdbool.h>
#include <stdint.h>

#define BUTTON_PIN 15u    /* GP15*/
#define TUP_TIMEOUT_MS 10000u   /* 10 s for button press */
#define DEBOUNCE_MS 50u   /* ignore bounce for 50 ms */
#define LED_PIN 25u    /* Pico built-in LED */

extern volatile bool s_tup_pending_for_ecdh;
extern volatile bool s_tup_pending_for_pubkey;

void tup_init(void);
void tup_request(void);
bool tup_check(void);
void tup_cancel(void);
bool tup_timed_out(void);