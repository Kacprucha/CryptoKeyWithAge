#include "crypto_handler.h"
#include "tusb.h"
#include "atca_basic.h"
#include "config_handler.h"
#include "protocol.h"
#include "user_presence.h"
#include <string.h>


void handle_get_random (const uint8_t *request_data, uint16_t request_len) 
{
    uint8_t random_bytes[32];
    uint8_t response[FRAME_OVERHEAD + 32];
    size_t out_len;
    uint8_t size = (request_len > 0) ? request_data[0] : 32;
    
    if (size > 32) 
    {
        size = 32;
    }
    
    ATCA_STATUS status = atcab_random(random_bytes);
    if (status != ATCA_SUCCESS) 
    {
        protocol_build_error (ERR_CHIP_FAIL, response, &out_len);
    }
    else 
    {
        protocol_build_response(CMD_GET_RANDOM, random_bytes, size, response, &out_len);
    }

    tud_cdc_write(response, out_len);
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

    /* TUP: check if user has pressed the button */
    if (!tup_check()) 
    {
        if (!s_tup_pending_for_ecdh) 
        {
            tup_request();
            s_tup_pending_for_ecdh = true;
        }

        uint8_t pending_info[2] = {
            (uint8_t)(TUP_WINDOW_MS / 1000),
            0x01 
        };

        protocol_build_response(CMD_USER_PRESENCE_PENDING, pending_info, sizeof(pending_info), tx_buf, &out_len);
        tud_cdc_write(tx_buf, out_len);
        tud_cdc_write_flush();
        return;
    }

    /* User has pressed the button - proceed with the cryptographic operation */
    s_tup_pending_for_ecdh = false;

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

void handle_get_public_key(const uint8_t *request_data, uint16_t request_len) 
{ 
    static uint8_t tx_buf[128];
    size_t out_len = 0;
    
    if (request_len < 1) 
    {
        protocol_build_error(ERR_BAD_LENGTH, tx_buf, &out_len);
        tud_cdc_write(tx_buf, out_len);
        tud_cdc_write_flush();
        return;
    }

    uint8_t slot = request_data[0];
    if (slot > 7) 
    {
        protocol_build_error(ERR_BAD_SLOT, tx_buf, &out_len);
        tud_cdc_write(tx_buf, out_len);
        tud_cdc_write_flush();
        return;
    }

	uint8_t pubkey[64]; 
	/* P-256: X(32B) || Y(32B) */ 
	uint8_t resp[FRAME_OVERHEAD + 64]; 
	ATCA_STATUS status = atcab_get_pubkey(slot, pubkey); 
	if (status != ATCA_SUCCESS) 
    { 
		protocol_build_error(ERR_CHIP_FAIL, resp, &out_len); 
	} 
    else 
    { 
		protocol_build_response(CMD_GET_PUBLIC_KEY, pubkey, 64, resp, &out_len);
	} 
    
	tud_cdc_write(resp, out_len); 
	tud_cdc_write_flush(); 
}

void handle_ecdh_request(const uint8_t *payload, uint16_t len, bool skip_tup_check)
{
    uint8_t shared_secret[32];
    uint8_t resp[FRAME_OVERHEAD + 32];
    size_t out_len;

    if (len != 65) 
    {
        protocol_build_error(ERR_BAD_LENGTH, resp, &out_len);
        tud_cdc_write(resp, out_len);
        tud_cdc_write_flush();
        return;
    }

    uint8_t slot = payload[0];
    const uint8_t *their_pub = payload + 1;

    if (slot > 7) 
    {
        protocol_build_error(ERR_BAD_SLOT, resp, &out_len);
        tud_cdc_write(resp, out_len);
        tud_cdc_write_flush();
        return;
    }

    /* TUP: check if user has pressed the button */
    if (!skip_tup_check && !tup_check()) 
    {
        if (!s_tup_pending_for_ecdh) 
        {
            tup_request();
            s_tup_pending_for_ecdh = true;
        }

        uint8_t pending_info[2] = {
            (uint8_t)(TUP_WINDOW_MS / 1000),
            0x01 
        };

        protocol_build_response(CMD_USER_PRESENCE_PENDING, pending_info, sizeof(pending_info), resp, &out_len);
        tud_cdc_write(resp, out_len);
        tud_cdc_write_flush();
        return;
    }

    /* User has pressed the button - proceed with the cryptographic operation */
    s_tup_pending_for_ecdh = false;

    bool x_zero = true, y_zero = true;
    for (int i = 0; i < 32; i++) 
    {
        if (their_pub[i] != 0) x_zero = false;
        if (their_pub[i+32] != 0) y_zero = false;
    }

    if (x_zero || y_zero) 
    {
        protocol_build_error(ERR_BAD_LENGTH, resp, &out_len);
        tud_cdc_write(resp, out_len);
        tud_cdc_write_flush();
        return;
    }

    ATCA_STATUS status = atcab_ecdh(slot, their_pub, shared_secret);
    if (status != ATCA_SUCCESS) 
    {
        protocol_build_error(ERR_CHIP_FAIL, resp, &out_len);
    } 
    else 
    {
        protocol_build_response(CMD_ECDH_REQUEST, shared_secret, 32, resp, &out_len);
        volatile uint8_t *p = shared_secret;
        for (int i = 0; i < 32; i++) p[i] = 0;
    }

    tud_cdc_write(resp, out_len);
    tud_cdc_write_flush();
}

void ecdh_request_with_i2c_time(const uint8_t *payload, uint16_t len, uint64_t *i2c_time_ms)
{
    uint8_t shared_secret[32];
    uint8_t resp[FRAME_OVERHEAD + 32];
    size_t out_len;

    if (len != 65) 
    {
        protocol_build_error(ERR_BAD_LENGTH, resp, &out_len);
        tud_cdc_write(resp, out_len);
        tud_cdc_write_flush();
        return;
    }

    uint8_t slot = payload[0];
    const uint8_t *their_pub = payload + 1;

    if (slot > 7) 
    {
        protocol_build_error(ERR_BAD_SLOT, resp, &out_len);
        tud_cdc_write(resp, out_len);
        tud_cdc_write_flush();
        return;
    }

    /* User has pressed the button - proceed with the cryptographic operation */
    s_tup_pending_for_ecdh = false;

    bool x_zero = true, y_zero = true;
    for (int i = 0; i < 32; i++) 
    {
        if (their_pub[i] != 0) x_zero = false;
        if (their_pub[i+32] != 0) y_zero = false;
    }

    if (x_zero || y_zero) 
    {
        protocol_build_error(ERR_BAD_LENGTH, resp, &out_len);
        tud_cdc_write(resp, out_len);
        tud_cdc_write_flush();
        return;
    }

    uint64_t start_time = time_us_64();
    ATCA_STATUS status = atcab_ecdh(slot, their_pub, shared_secret);
    uint64_t end_time = time_us_64();
    *i2c_time_ms = (end_time - start_time) / 1000; // Convert microseconds to milliseconds
    
    // if (status != ATCA_SUCCESS) 
    // {
    //     protocol_build_error(ERR_CHIP_FAIL, resp, &out_len);
    // } 
    // else 
    // {
    //     protocol_build_response(CMD_ECDH_REQUEST, shared_secret, 32, resp, &out_len);
    //     volatile uint8_t *p = shared_secret;
    //     for (int i = 0; i < 32; i++) p[i] = 0;
    // }

    // tud_cdc_write(resp, out_len);
    // tud_cdc_write_flush();
}

void handle_get_i2c_time(const uint8_t *req_data, uint16_t req_len) 
{
    static uint8_t tx_buf[128];
    size_t out_len = 0;

    uint64_t i2c_time_ms = 0;
    ecdh_request_with_i2c_time(req_data, req_len, &i2c_time_ms);
    protocol_build_response(CMD_GET_I2C_TIME, (uint8_t*)&i2c_time_ms, sizeof(i2c_time_ms), tx_buf, &out_len);

    tud_cdc_write(tx_buf, out_len);
    tud_cdc_write_flush();
}


