#include "protocol.h"
#include <string.h>

uint32_t protocol_crc32 (const uint8_t *data, size_t len) 
{
    uint32_t crc = 0xFFFFFFFF;

    for (size_t i = 0; i < len; i++) 
    {
        crc ^= data[i];
        for (int j = 0; j < 8; j++) 
        {
            crc = (crc >> 1) ^ (0xEDB88320u & -(crc & 1));
        }
    }

    return crc ^ 0xFFFFFFFF;
}

bool protocol_build_response (uint8_t cmd, const uint8_t *data, uint16_t len, uint8_t *out, size_t *out_len) 
{
    if (len > MAX_PAYLOAD)
        return false;

    out[0] = STX;
    out[1] = cmd;
    out[2] = len & 0xFF;
    out[3] = (len >> 8) & 0xFF;
    memcpy(out + FRAME_HEADR_SIZE, data, len);

    uint32_t crc = protocol_crc32(out, FRAME_HEADR_SIZE + len);
    memcpy (out + FRAME_HEADR_SIZE + len, &crc, sizeof(crc));
    *out_len = FRAME_OVERHEAD + len;
    return true;
}

bool protocol_build_error (uint8_t error_code, uint8_t *out, size_t *out_len) 
{
    return protocol_build_response(CMD_ERROR, &error_code, 1, out, out_len);
}

bool protocol_parse_frame (const uint8_t *frame, size_t frame_len, frame_t *out) 
{
    if (frame_len < FRAME_OVERHEAD || frame[0] != STX)
        return false;

    uint16_t payload_len = (uint16_t)frame[2] | ((uint16_t)frame[3] << 8);
    if (payload_len > MAX_PAYLOAD || frame_len < FRAME_OVERHEAD + payload_len)
        return false;

    uint32_t received_crc;
    memcpy(&received_crc, frame + FRAME_HEADR_SIZE + payload_len, sizeof(received_crc));
    uint32_t calculated_crc = protocol_crc32(frame, FRAME_HEADR_SIZE + payload_len);

    if (received_crc != calculated_crc)
        return false;

    out->cmd = frame[1];
    out->len = payload_len;
    memcpy(out->data, frame + FRAME_HEADR_SIZE, payload_len);
    
    return true;
}