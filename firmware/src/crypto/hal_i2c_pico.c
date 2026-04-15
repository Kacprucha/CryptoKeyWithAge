#include "cryptoauthlib.h" 
#include "hardware/i2c.h" 
#include "pico/stdlib.h" 
#include <string.h>

#define ATECC608A_I2C_ADDR_8BIT  0xC0u  /* CryptoAuthLib (8-bit) format*/
#define ATECC608A_I2C_ADDR_7BIT  (ATECC608A_I2C_ADDR_8BIT >> 1)  /* = 0x60, for RP2040 API */

void atca_delay_ms(uint32_t ms) {
    sleep_ms(ms);
}

void atca_delay_us(uint32_t us) {
    sleep_us(us);
}

ATCA_STATUS hal_i2c_init(ATCAIface iface, ATCAIfaceCfg *cfg) 
{ 
	(void) iface; 
	(void) cfg; 

	// i2c_init(i2c0, 400 * 1000);
	// gpio_set_function(4, GPIO_FUNC_I2C); 
	// gpio_set_function(5, GPIO_FUNC_I2C); 

	// gpio_pull_up(4); 
	// gpio_pull_up(5); 

	return ATCA_SUCCESS; 
} 

ATCA_STATUS hal_i2c_send(ATCAIface iface, uint8_t word_addr, uint8_t *txdata, int txlen) 
{ 
	(void) iface; 
	static uint8_t buf[ATCA_PACKET_SIZE + 1];

	if (txlen + 1 > (int)sizeof(buf)) return ATCA_BAD_PARAM;
	buf[0] = word_addr; 
	memcpy(buf + 1, txdata, txlen); 

	int r = i2c_write_blocking(i2c0, ATECC608A_I2C_ADDR_7BIT, buf, txlen + 1, false);

	return (r == PICO_ERROR_GENERIC) ? ATCA_COMM_FAIL : ATCA_SUCCESS; 
} 

ATCA_STATUS hal_i2c_receive(ATCAIface iface, uint8_t word_addr, uint8_t *rxdata, uint16_t *rxlen) 
{ 
	(void) iface; 
	(void) word_addr; 

	int r = i2c_read_blocking(i2c0, ATECC608A_I2C_ADDR_7BIT, rxdata, *rxlen, false);

	return (r == PICO_ERROR_GENERIC) ? ATCA_COMM_FAIL : ATCA_SUCCESS; 
} 

ATCA_STATUS hal_i2c_wake(ATCAIface iface) 
{ 
	(void) iface;

	//i2c_set_baudrate(i2c0, 100 * 1000);

	uint8_t wake_token = 0x00;
	i2c_write_blocking(i2c0, 0x00, &wake_token, 1, false);

	sleep_us(1500);

	//i2c_set_baudrate(i2c0, 400 * 1000);

	return ATCA_SUCCESS; 
}

ATCA_STATUS hal_i2c_idle(ATCAIface iface) 
{
	(void) iface;
	uint8_t idle_token = 0x02;

	i2c_write_blocking(i2c0, ATECC608A_I2C_ADDR_7BIT, &idle_token, 1, false);

	return ATCA_SUCCESS;
}

ATCA_STATUS hal_i2c_sleep(ATCAIface iface) 
{
	(void) iface;
	uint8_t sleep_token = 0x01;

	i2c_write_blocking(i2c0, ATECC608A_I2C_ADDR_7BIT, &sleep_token, 1, false);

	return ATCA_SUCCESS;
}

ATCA_STATUS hal_i2c_release(void *hal_data)
{ 
	(void) hal_data; 
	return ATCA_SUCCESS; 
}

ATCA_STATUS hal_i2c_post_init(ATCAIface iface) {
    (void)iface;
    return ATCA_SUCCESS;
}

ATCA_STATUS hal_i2c_control(ATCAIface iface, uint8_t option,
                             void *param, size_t paramlen) {
    (void)iface;
    (void)option;
    (void)param;
    (void)paramlen;
    return ATCA_UNIMPLEMENTED;
}