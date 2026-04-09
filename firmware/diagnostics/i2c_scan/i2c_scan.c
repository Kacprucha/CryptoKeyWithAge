#include <stdio.h>
#include "pico/stdlib.h"
#include "hardware/i2c.h"

// I2C defines
// This example will use I2C0 on GPIO8 (SDA) and GPIO9 (SCL) running at 400KHz.
// Pins can be changed, see the GPIO function select table in the datasheet for information on GPIO assignments
#define I2C_PORT i2c0
#define I2C_SDA 4
#define I2C_SCL 5

int main()
{
    stdio_init_all();

    sleep_ms(3000);

    // I2C Initialisation. Using it at 100Khz.
    i2c_init(I2C_PORT, 100*1000);
    
    gpio_set_function(I2C_SDA, GPIO_FUNC_I2C);
    gpio_set_function(I2C_SCL, GPIO_FUNC_I2C);
    gpio_pull_up(I2C_SDA);
    gpio_pull_up(I2C_SCL);
    // For more examples of I2C use see https://github.com/raspberrypi/pico-examples/tree/master/i2c

    sleep_ms(1000);

    printf("I2C scan:\n");
    for (int addr = 0x08; addr < 0x78; addr++)
    {
        uint8_t dummy;
        int result = i2c_read_blocking(i2c0, addr, &dummy, 1, false);
        if (result >= 0)
            printf("Device found at 0x%02X\n", addr);
    }
    printf("Scan complete.\n");

    while (true)
        tight_loop_contents();
}
