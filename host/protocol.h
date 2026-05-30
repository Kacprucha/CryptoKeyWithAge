#pragma once
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#define STX 0x02
#define CMD_GET_STATUS 0x01
#define CMD_GET_PUBLIC_KEY 0x02
#define CMD_ECDH_REQUEST 0x03
#define CMD_GET_RANDOM 0x04
#define CMD_GEN_KEY 0x05
#define CMD_USER_PRESENCE_PENDING 0x06
#define CMD_ECDH_REQUEST_BYPASS_TUP 0x07
#define CMD_ERROR 0xFF

#define ERR_UNKNOWN_CMD 0x01
#define ERR_BAD_CRC 0x02
#define ERR_BAD_LENGTH 0x03
#define ERR_CHIP_FAIL 0x04
#define ERR_BAD_SLOT 0x05
#define ERR_USER_PRESENCE_REQUIRED 0x06 
#define ERR_USER_PRESENCE_TIMEOUT  0x07

#define FRAME_HEADR_SIZE 4
#define FRAME_CRC_SIZE 4
#define FRAME_OVERHEAD (FRAME_HEADR_SIZE + FRAME_CRC_SIZE)
#define MAX_PAYLOAD 255
#define TUP_WINDOW_MS 10000 /* must be the same as TUP_TIMEOUT_MS in user_presence.h */

typedef struct 
{
    uint8_t cmd;
    uint8_t data[MAX_PAYLOAD];
    uint16_t len;
}
frame_t;

uint32_t protocol_crc32 (const uint8_t *data, size_t len);
bool protocol_build_frame (uint8_t cmd, const uint8_t *data, uint16_t len, uint8_t *out, size_t *out_len);
bool protocol_parse_response (const uint8_t *raw, size_t raw_len, uint8_t *cmd_out, uint8_t *data_out, uint16_t *len_out); 
