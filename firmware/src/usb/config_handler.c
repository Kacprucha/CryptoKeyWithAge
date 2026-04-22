/**
 * firmware/src/usb/config_handler.c
 *
 * Obsługa komendy CMD_CONFIG_OP (0x10) w firmware Pico.
 *
 * Dodaj do switch(frame.cmd) w usb_handler.c:
 *   case CMD_CONFIG_OP:
 *       handle_config_op(frame.data, frame.len);
 *       break;
 *
 * Dodaj do usb_handler.h:
 *   #define CMD_CONFIG_OP  0x10
 *
 * Dodaj do CMakeLists.txt:
 *   src/usb/config_handler.c
 */

#include "config_handler.h"
#include "atecc608a_config.h"
#include "protocol.h"
#include "tusb.h"
#include <string.h>

/* Podkomendy operacji konfiguracyjnych */
#define OP_READ_CONFIG    0x01
#define OP_WRITE_CONFIG   0x02
#define OP_LOCK_CONFIG    0x03
#define OP_LOCK_DATA      0x04

/* =========================================================================
 * handle_config_op()
 *
 * Wywoływana z usb_handler.c gdy nadchodzi CMD_CONFIG_OP.
 * req_data[0] = kod operacji (OP_*)
 * ========================================================================= */
void handle_config_op(const uint8_t *req_data, uint16_t req_len) {
    static uint8_t tx_buf[256];
    size_t out_len = 0;

    if (req_len < 1) {
        protocol_build_error(ERR_BAD_LENGTH, tx_buf, &out_len);
        tud_cdc_write(tx_buf, out_len);
        tud_cdc_write_flush();
        return;
    }

    uint8_t op = req_data[0];

    switch (op) {

    /* ------------------------------------------------------------------ */
    case OP_READ_CONFIG: {
        /* Odczytaj 128B config zone i odeślij */
        uint8_t cfg[128];
        ATCA_STATUS status = atecc608a_read_config(cfg);
        if (status != ATCA_SUCCESS) {
            printf("atcab_init failed: %d\n", status);
  
            protocol_build_error(ERR_CHIP_FAIL, tx_buf, &out_len);
        } else {
            protocol_build_response(CMD_CONFIG_OP, cfg, 128, tx_buf, &out_len);
        }
        break;
    }

    /* ------------------------------------------------------------------ */
    case OP_WRITE_CONFIG: {
        /* Zapisz docelową konfigurację */
        ATCA_STATUS status = atecc608a_write_config();
        uint8_t result = (status == ATCA_SUCCESS) ? 0x00 : (uint8_t)status;
        if (status != ATCA_SUCCESS) {
            protocol_build_error(ERR_CHIP_FAIL, tx_buf, &out_len);
        } else {
            protocol_build_response(CMD_CONFIG_OP, &result, 1, tx_buf, &out_len);
        }
        break;
    }

    /* ------------------------------------------------------------------ */
    case OP_LOCK_CONFIG: {
        /* Zablokuj config zone – wywołaj tylko po verify */
        ATCA_STATUS status = atecc608a_lock_config_zone(true);
        if (status != ATCA_SUCCESS) {
            protocol_build_error(ERR_CHIP_FAIL, tx_buf, &out_len);
        } else {
            uint8_t ok = 0x00;
            protocol_build_response(CMD_CONFIG_OP, &ok, 1, tx_buf, &out_len);
        }
        break;
    }

    /* ------------------------------------------------------------------ */
    case OP_LOCK_DATA: {
        /* Zablokuj data/OTP zone */
        ATCA_STATUS status = atecc608a_lock_data_zone(true);
        if (status != ATCA_SUCCESS) {
            protocol_build_error(ERR_CHIP_FAIL, tx_buf, &out_len);
        } else {
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

/* =========================================================================
 * handle_gen_key()  (CMD_GEN_KEY = 0x07)
 *
 * Payload[0] = slot (0-7)
 * Odpowiedź: 64B klucz publiczny (X||Y)
 *
 * Dodaj do switch(frame.cmd):
 *   case CMD_GEN_KEY:
 *       handle_gen_key(frame.data, frame.len);
 *       break;
 * ========================================================================= */
void handle_gen_key(const uint8_t *req_data, uint16_t req_len) {
    static uint8_t tx_buf[128];
    size_t out_len = 0;

    if (req_len < 1) {
        protocol_build_error(ERR_BAD_LENGTH, tx_buf, &out_len);
        tud_cdc_write(tx_buf, out_len);
        tud_cdc_write_flush();
        return;
    }

    uint8_t slot = req_data[0];
    if (slot > 7) {
        protocol_build_error(ERR_BAD_LENGTH, tx_buf, &out_len);
        tud_cdc_write(tx_buf, out_len);
        tud_cdc_write_flush();
        return;
    }

    uint8_t pubkey[64];
    /* atcab_genkey(slot, pubkey) – GenKey Mode 0x04:
     * Generuje NOWY losowy klucz prywatny w podanym slocie.
     * NISZCZY poprzedni klucz (nieodwracalne).
     * Zwraca odpowiadający klucz publiczny (64B: X||Y bez prefiksu). */
    ATCA_STATUS status = atcab_genkey(slot, pubkey);

    if (status != ATCA_SUCCESS) {
        /* Częste przyczyny błędu:
         * - ATCA_EXECUTION_ERROR: data zone niezablokowana
         * - ATCA_BAD_PARAM: nieprawidłowy slot
         * - ECC fault: losowy błąd ECC (retry działa) */
        //uint8_t detail[1] = { (uint8_t)status };
        //protocol_build_response(0xFF, detail, 1, tx_buf, &out_len);
        protocol_build_error(ERR_CHIP_FAIL, tx_buf, &out_len);
    } else {
        protocol_build_response(CMD_GEN_KEY, pubkey, 64, tx_buf, &out_len);
    }

    tud_cdc_write(tx_buf, out_len);
    tud_cdc_write_flush();
}

/* =========================================================================
 * handle_get_public_key()  (CMD_GET_PUBLIC_KEY = 0x02)
 *
 * Zaktualizowana wersja obsługująca slot jako parametr.
 * Payload[0] = slot (0-7), domyślnie 0 jeśli len == 0.
 * ========================================================================= */
void handle_get_public_key_slotted(const uint8_t *req_data, uint16_t req_len) {
    static uint8_t tx_buf[128];
    size_t out_len = 0;

    uint8_t slot = (req_len > 0) ? req_data[0] : 0;
    if (slot > 7) {
        protocol_build_error(ERR_BAD_LENGTH, tx_buf, &out_len);
        tud_cdc_write(tx_buf, out_len);
        tud_cdc_write_flush();
        return;
    }

    uint8_t pubkey[64];
    /* atcab_get_pubkey(slot, pubkey) – GenKey Mode 0x00:
     * Oblicza klucz publiczny z ISTNIEJĄCEGO klucza prywatnego.
     * NIE generuje nowego klucza. Jeśli slot pusty → błąd. */
    ATCA_STATUS status = atcab_get_pubkey(slot, pubkey);

    if (status != ATCA_SUCCESS) {
        protocol_build_error(ERR_CHIP_FAIL, tx_buf, &out_len);
    } else {
        protocol_build_response(CMD_GET_PUBLIC_KEY, pubkey, 64, tx_buf, &out_len);
    }

    tud_cdc_write(tx_buf, out_len);
    tud_cdc_write_flush();
}

/* =========================================================================
 * handle_ecdh_slotted()  (CMD_ECDH_REQUEST = 0x03)
 *
 * Zaktualizowana wersja obsługująca slot jako parametr.
 * Payload[0] = slot (0-7)
 * Payload[1..64] = klucz publiczny drugiej strony (X||Y, 64B)
 * ========================================================================= */
void handle_ecdh_slotted(const uint8_t *req_data, uint16_t req_len) {
    static uint8_t tx_buf[128];
    size_t out_len = 0;

    /* Oczekujemy 1B slot + 64B pubkey = 65B */
    if (req_len != 65) {
        protocol_build_error(ERR_BAD_LENGTH, tx_buf, &out_len);
        tud_cdc_write(tx_buf, out_len);
        tud_cdc_write_flush();
        return;
    }

    uint8_t slot        = req_data[0];
    const uint8_t *pub  = req_data + 1;

    if (slot > 7) {
        protocol_build_error(ERR_BAD_LENGTH, tx_buf, &out_len);
        tud_cdc_write(tx_buf, out_len);
        tud_cdc_write_flush();
        return;
    }

    /* Walidacja punktu – sprawdź czy nie jest punktem w nieskończoności */
    bool x_zero = true, y_zero = true;
    for (int i = 0; i < 32; i++) {
        if (pub[i]    != 0) x_zero = false;
        if (pub[i+32] != 0) y_zero = false;
    }
    if (x_zero || y_zero) {
        protocol_build_error(ERR_BAD_LENGTH, tx_buf, &out_len);
        tud_cdc_write(tx_buf, out_len);
        tud_cdc_write_flush();
        return;
    }

    uint8_t shared_secret[32];
    ATCA_STATUS status = atcab_ecdh(slot, pub, shared_secret);

    if (status != ATCA_SUCCESS) {
        protocol_build_error(ERR_CHIP_FAIL, tx_buf, &out_len);
    } else {
        protocol_build_response(CMD_ECDH_REQUEST, shared_secret, 32, tx_buf, &out_len);
        /* Wyzeruj shared_secret z RAM */
        volatile uint8_t *p = shared_secret;
        for (int i = 0; i < 32; i++) p[i] = 0;
    }

    tud_cdc_write(tx_buf, out_len);
    tud_cdc_write_flush();
}
