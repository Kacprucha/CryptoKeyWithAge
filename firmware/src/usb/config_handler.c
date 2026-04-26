#include "config_handler.h"
#include "atecc608a_config.h"
#include "protocol.h"
#include "tusb.h"
#include <string.h>

/* Subcommands for config operations */
#define OP_READ_CONFIG    0x01
#define OP_WRITE_CONFIG   0x02
#define OP_LOCK_CONFIG    0x03
#define OP_LOCK_DATA      0x04

void handle_config_op(const uint8_t *req_data, uint16_t req_len) 
{
    static uint8_t tx_buf[256];
    size_t out_len = 0;

    if (req_len < 1) 
    {
        protocol_build_error(ERR_BAD_LENGTH, tx_buf, &out_len);
        tud_cdc_write(tx_buf, out_len);
        tud_cdc_write_flush();
        return;
    }

    uint8_t op = req_data[0];

    switch (op) {

    /* ------------------------------------------------------------------ */
    case OP_READ_CONFIG: 
    {
        uint8_t cfg[128];
        ATCA_STATUS status = atecc608a_read_config(cfg);

        if (status != ATCA_SUCCESS) 
        {
            printf("atcab_init failed: %d\n", status);
  
            protocol_build_error(ERR_CHIP_FAIL, tx_buf, &out_len);
        } 
        else 
        {
            protocol_build_response(CMD_CONFIG_OP, cfg, 128, tx_buf, &out_len);
        }

        break;
    }

    /* ------------------------------------------------------------------ */
    case OP_WRITE_CONFIG: 
    {
        ATCA_STATUS status = atecc608a_write_config();
        uint8_t result = (status == ATCA_SUCCESS) ? 0x00 : (uint8_t)status;

        if (status != ATCA_SUCCESS) 
        {
            protocol_build_error(ERR_CHIP_FAIL, tx_buf, &out_len);
        } 
        else 
        {
            protocol_build_response(CMD_CONFIG_OP, &result, 1, tx_buf, &out_len);
        }

        break;
    }

    /* ------------------------------------------------------------------ */
    case OP_LOCK_CONFIG: 
    {
        ATCA_STATUS status = atecc608a_lock_config_zone(true);

        if (status != ATCA_SUCCESS) 
        {
            protocol_build_error(ERR_CHIP_FAIL, tx_buf, &out_len);
        } 
        else 
        {
            uint8_t ok = 0x00;
            protocol_build_response(CMD_CONFIG_OP, &ok, 1, tx_buf, &out_len);
        }

        break;
    }

    /* ------------------------------------------------------------------ */
    case OP_LOCK_DATA: 
    {
        ATCA_STATUS status = atecc608a_lock_data_zone(true);

        if (status != ATCA_SUCCESS) 
        {
            protocol_build_error(ERR_CHIP_FAIL, tx_buf, &out_len);
        } 
        else 
        {
            uint8_t ok = 0x00;
            protocol_build_response(CMD_CONFIG_OP, &ok, 1, tx_buf, &out_len);
        }

        break;
    }

    /* ------------------------------------------------------------------ */
    default:
        protocol_build_error(ERR_UNKNOWN_CMD, tx_buf, &out_len);
        break;
    }

    tud_cdc_write(tx_buf, out_len);
    tud_cdc_write_flush();
}

void handle_gen_key(const uint8_t *req_data, uint16_t req_len) 
{
    static uint8_t tx_buf[128];
    size_t out_len = 0;

    if (req_len < 1) 
    {
        protocol_build_error(ERR_BAD_LENGTH, tx_buf, &out_len);
        tud_cdc_write(tx_buf, out_len);
        tud_cdc_write_flush();
        return;
    }

    uint8_t slot = req_data[0];
    if (slot > 7) 
    {
        protocol_build_error(ERR_BAD_LENGTH, tx_buf, &out_len);
        tud_cdc_write(tx_buf, out_len);
        tud_cdc_write_flush();
        return;
    }

    uint8_t pubkey[64];
    /* atcab_genkey(slot, pubkey) – GenKey Mode 0x04:
     * Generating NEW random private key in the specified slot.
     * DESTROYS the previous key (irreversible).
     * Returns the corresponding public key (64B: X||Y without prefix). */
    ATCA_STATUS status = atcab_genkey(slot, pubkey);

    if (status != ATCA_SUCCESS) 
    {
        /* Frequent reasons for error:
         * - ATCA_EXECUTION_ERROR: data zone not locked
         * - ATCA_BAD_PARAM: invalid slot
         * - ECC fault: random ECC error (retry works) */
        protocol_build_error(ERR_CHIP_FAIL, tx_buf, &out_len);
    } 
    else 
    {
        protocol_build_response(CMD_GEN_KEY, pubkey, 64, tx_buf, &out_len);
    }

    tud_cdc_write(tx_buf, out_len);
    tud_cdc_write_flush();
}

void handle_get_public_key_slotted(const uint8_t *req_data, uint16_t req_len) 
{
    static uint8_t tx_buf[128];
    size_t out_len = 0;

    uint8_t slot = (req_len > 0) ? req_data[0] : 0;
    if (slot > 7) 
    {
        protocol_build_error(ERR_BAD_LENGTH, tx_buf, &out_len);
        tud_cdc_write(tx_buf, out_len);
        tud_cdc_write_flush();
        return;
    }

    uint8_t pubkey[64];
    /* atcab_get_pubkey(slot, pubkey) – GenKey Mode 0x00:
     * Calculating public key from EXISTING private key.
     * DOES NOT generate a new key. If slot is empty → error. */
    ATCA_STATUS status = atcab_get_pubkey(slot, pubkey);

    if (status != ATCA_SUCCESS) 
    {
        protocol_build_error(ERR_CHIP_FAIL, tx_buf, &out_len);
    } 
    else 
    {
        protocol_build_response(CMD_GET_PUBLIC_KEY, pubkey, 64, tx_buf, &out_len);
    }

    tud_cdc_write(tx_buf, out_len);
    tud_cdc_write_flush();
}

void handle_ecdh_slotted(const uint8_t *req_data, uint16_t req_len) 
{
    static uint8_t tx_buf[128];
    size_t out_len = 0;

    if (req_len != 65) 
    {
        protocol_build_error(ERR_BAD_LENGTH, tx_buf, &out_len);
        tud_cdc_write(tx_buf, out_len);
        tud_cdc_write_flush();
        return;
    }

    uint8_t slot = req_data[0];
    const uint8_t *pub = req_data + 1;

    if (slot > 7) 
    {
        protocol_build_error(ERR_BAD_LENGTH, tx_buf, &out_len);
        tud_cdc_write(tx_buf, out_len);
        tud_cdc_write_flush();
        return;
    }

    bool x_zero = true, y_zero = true;
    for (int i = 0; i < 32; i++) 
    {
        if (pub[i]    != 0) x_zero = false;
        if (pub[i+32] != 0) y_zero = false;
    }

    if (x_zero || y_zero) 
    {
        protocol_build_error(ERR_BAD_LENGTH, tx_buf, &out_len);
        tud_cdc_write(tx_buf, out_len);
        tud_cdc_write_flush();
        return;
    }

    uint8_t shared_secret[32];
    ATCA_STATUS status = atcab_ecdh(slot, pub, shared_secret);

    if (status != ATCA_SUCCESS) 
    {
        protocol_build_error(ERR_CHIP_FAIL, tx_buf, &out_len);
    } 
    else 
    {
        protocol_build_response(CMD_ECDH_REQUEST, shared_secret, 32, tx_buf, &out_len);
        volatile uint8_t *p = shared_secret;
        for (int i = 0; i < 32; i++) p[i] = 0;
    }

    tud_cdc_write(tx_buf, out_len);
    tud_cdc_write_flush();
}
