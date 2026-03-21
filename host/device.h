#pragma once
#include "protocol.h"
#include <fcntl.h>
#include <termios.h>
#include <unistd.h>

int device_open(const char *path);
int device_send_cmd (int fd, uint8_t cmd, const uint8_t *data, uint16_t data_len, uint8_t *resp_data, uint16_t *resp_len);
void device_close (int fd);