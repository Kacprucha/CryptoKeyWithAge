#ifndef DEVICE_DEVICE_TUP_H
#define DEVICE_DEVICE_TUP_H

#include <stdint.h>

int pgp_device_send_cmd_tup(int fd, uint8_t cmd, const uint8_t *data, uint16_t data_len, uint8_t *resp_data, uint16_t *resp_len);

#endif