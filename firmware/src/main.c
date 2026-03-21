#include <stdio.h>
#include "pico/stdlib.h"
#include "tusb.h"

int main() 
{
    stdio_init_all();
    tusb_init(BOARD_TUD_RHPORT, BOARD_TUD_MAX_SPEED);

    while (true) 
    {
        tud_task(); // tinyusb device task
    }

    return 0;
}