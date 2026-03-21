#pragma once
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#define STX 0x02
#define CMD_GET_STATUS 0x01
#define CMD_GET_PUBLIC_KEY 0x02
#define CMD_ECDH_REQUEST 0x03
#define CMD_GET_RANDOM 0x04
#define CMD_ERROR 0xFF

#define ERR_UKNOWN_CMD 0x01
#define ERR_BAD_CRC 0x02
#define ERR_BAD_LENGTH 0x03
#define ERR_CHIP_FAIL 0x04

#define FRAME_HEADR_SIZE 4
#define FRAME_CRC_SIZE 4
#define FRAME_OVERHEAD (FRAME_HEADR_SIZE + FRAME_CRC_SIZE)
#define MAX_PAYLOAD 255

typedef struct 
{
    uint8_t cmd;
    uint8_t data[MAX_PAYLOAD];
    uint16_t len;
}
frame_t;

uint32_t protocol_crc32 (const uint8_t *data, size_t len);
bool protocol_build_response (uint8_t cmd, const uint8_t *data, uint16_t len, uint8_t *out, size_t *out_len);
bool protocol_build_error (uint8_t error_code, uint8_t *out, size_t *out_len);
bool protocol_parse_frame (const uint8_t *frame, size_t frame_len, frame_t *out);
