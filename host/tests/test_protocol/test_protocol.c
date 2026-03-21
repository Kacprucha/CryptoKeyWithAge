#include "protocol.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

static void test_roundtrip (void) 
{
    uint8_t frame[FRAME_OVERHEAD + MAX_PAYLOAD];
    size_t frame_len;
    uint8_t resp_cmd;
    uint8_t resp_data[MAX_PAYLOAD];
    uint16_t resp_len;

    protocol_build_frame (CMD_GET_STATUS | 0x80, NULL, 0, frame, &frame_len);

    bool ok = protocol_parse_response (frame, frame_len, &resp_cmd, resp_data, &resp_len);
    assert(ok);
    assert(resp_cmd == (CMD_GET_STATUS | 0x80));
    assert(resp_len == 0);
    printf("[test_roundtrip]\tTest passed: Roundtrip frame build and parse\n");
}

void test_crc_detection (void) 
{
    uint8_t frame[FRAME_OVERHEAD + MAX_PAYLOAD];
    size_t frame_len;
    uint8_t payload[] = "Test payload";

    protocol_build_frame (CMD_GET_STATUS, payload, sizeof(payload) - 1, frame, &frame_len);

    frame[frame_len - 1] ^= 0xFF; // Corrupt the CRC
    uint8_t resp_cmd;
    uint8_t resp_data[MAX_PAYLOAD];
    uint16_t resp_len;

    bool ok = protocol_parse_response (frame, frame_len, &resp_cmd, resp_data, &resp_len);
    assert(!ok);
    printf("[test_crc_detection]\tTest passed: CRC error correctly detected\n");
}

static void test_partial_frame (void) 
{
    uint8_t frame[FRAME_OVERHEAD + MAX_PAYLOAD];
    size_t frame_len;
    uint8_t payload[] = "Test payload";

    protocol_build_frame (CMD_GET_STATUS, payload, sizeof(payload) - 1, frame, &frame_len);

    uint8_t resp_cmd;
    uint8_t resp_data[MAX_PAYLOAD];
    uint16_t resp_len;

    bool ok = protocol_parse_response (frame, frame_len / 2, &resp_cmd, resp_data, &resp_len);
    assert(!ok);
    ok = protocol_parse_response(frame, frame_len, &resp_cmd, resp_data, &resp_len);
    assert(ok);
    printf("[test_partial_frame]\tTest passed: Partial frame correctly rejected\n");
}

int main (void) 
{
    test_roundtrip();
    test_crc_detection();
    test_partial_frame();
    printf("\nAll protocol tests passed successfully\n");
    return 0;
}