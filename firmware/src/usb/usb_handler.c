#include "tusb.h"
#include "atca_basic.h"
#include "config_handler.h"
#include "crypto_handler.h"
#include "protocol.h"
#include <string.h>

#define RX_BUF_SIZE 256

static uint8_t rx_buf[RX_BUF_SIZE];
static uint8_t tx_buf[RX_BUF_SIZE];
static uint32_t rx_pos = 0;
static const uint8_t VERSION[] = "v0.1-c-firmware";

static void handle_get_status (void) 
{
    size_t out_len;
    protocol_build_response(CMD_GET_STATUS, VERSION, sizeof(VERSION) - 1, tx_buf, &out_len);
    
    tud_cdc_write(tx_buf, out_len);
    tud_cdc_write_flush();
}

void tud_cdc_rx_cb(uint8_t itf) 
{
    (void) itf;
    uint32_t count = tud_cdc_read(rx_buf + rx_pos, sizeof(rx_buf) - rx_pos);
    rx_pos += count;
    frame_t frame;

    if (rx_pos < FRAME_OVERHEAD)
        return;

    if (!protocol_parse_frame(rx_buf, rx_pos, &frame)) 
    {
        if (rx_buf[0] != STX) 
        {
            uint32_t stx_pos = 1;
            while (stx_pos < rx_pos && rx_buf[stx_pos] != STX)
                stx_pos++;

            memmove(rx_buf, rx_buf + stx_pos, rx_pos - stx_pos);
            rx_pos -= stx_pos;

            if (rx_pos > 0 || stx_pos > 0) 
            {
                size_t out_len;
                protocol_build_error (ERR_BAD_CRC, tx_buf, &out_len);
                tud_cdc_write(tx_buf, out_len);
                tud_cdc_write_flush();
            }
        }

        return;
    }

    uint32_t consumed = FRAME_OVERHEAD + frame.len;
    memmove(rx_buf, rx_buf + consumed, rx_pos - consumed);
    rx_pos -= consumed;

    printf("FRAME cmd=%02x, len=%u\n", frame.cmd, frame.len);
    for (int i = 0; i < frame.len; i++) {
        printf("%02x ", frame.data[i]);
    }
    printf("\n");

    switch (frame.cmd) 
    {
        case CMD_GET_STATUS:
            handle_get_status();
            break;
        case CMD_GET_PUBLIC_KEY:
            handle_get_public_key(frame.data, frame.len);
            break;
        case CMD_GET_RANDOM:
            handle_get_random(frame.data, frame.len);
            break;
        case CMD_CONFIG_OP:
            handle_config_op(frame.data, frame.len);
            break;
        case CMD_GEN_KEY:
            handle_gen_key(frame.data, frame.len);
            break;
        case CMD_ECDH_REQUEST:
            handle_ecdh_request(frame.data, frame.len);
            break;
        default:
            size_t out_len;
            protocol_build_error (ERR_UNKNOWN_CMD, tx_buf, &out_len);
            tud_cdc_write(tx_buf, out_len);
            tud_cdc_write_flush();
            break;
    }
}