#pragma once
#include "protocol.h"
#include <fcntl.h>
#include <termios.h>
#include <unistd.h>

#define TUP_POLL_INTERVAL_MS  500
#define TUP_MAX_POLLS          25 

int device_open(const char *path);
int device_send_cmd (int fd, uint8_t cmd, const uint8_t *data, uint16_t data_len, uint8_t *cmd_out, uint8_t *resp_data, uint16_t *resp_len);
void device_close (int fd);
int device_send_cmd_tup(int fd, uint8_t cmd, const uint8_t *data, uint16_t data_len, uint8_t *resp_data, uint16_t *resp_len);