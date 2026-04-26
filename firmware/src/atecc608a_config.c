/**
 * Config Zone configutation function implementation for ATECC608A.
 *
 *  Order of use (safe workflow):
 *   1. atecc608a_read_config()    → read current configuration
 *   2. atecc608a_print_config()   → visually inspect
 *   3. atecc608a_write_config()   → write target configuration
 *   4. atecc608a_verify_config()  → ensure write was successful
 *   5. atecc608a_print_config()   → re-inspect
 *   6. atecc608a_lock_config_zone(true)  ← IRREVERSIBLE
 *   7. atecc608a_lock_data_zone(true)    ← IRREVERSIBLE 
 */

#include "atecc608a_config.h"
#include <stdio.h>
#include <string.h>
#include "atca_basic.h"

/* ================================================================================
* TARGET VALUE TABLES
* ==================================================================================
*
* ENDIANNESS – KEY POINT:
*
* The datasheet (section 4.1) states:
* "16-bit (2-byte) integers, typically Param2, SlotConfig, or KeyConfig,
* appear on the bus least-significant byte first."

*
* This means that in the EEPROM (and in the buffer returned by atcab_read_config_zone):
* cfg[20] = LOW byte (bits 7:0) SlotConfig[0]
* cfg[21] = HIGH byte (bits 15:8) SlotConfig[0]
* cfg[22] = LOW byte SlotConfig[1]
* cfg[23] = HIGH byte SlotConfig[1]
* ...
*
* We arrange the TARGET_* arrays in the same order: [LO, HI, LO, HI, ...].
* atcab_write_bytes_zone() passes the bytes to the chip without any conversion –
* we supply the chip with the bytes exactly as they are in the EEPROM. *
* When reading and decoding, we reassemble the uint16_t with:
* uint16_t sc = (uint16_t)lo | ((uint16_t)hi << 8);
* which recreates the full value with the correct bit assignment to the fields.
* ================================================================================== */

/*
* Target SlotConfig[0..15] – 32 bytes (2B per slot, little-endian in EEPROM).
* Array order: [slot_low_byte_0, slot_high_byte_0, slot_low_byte_1, ...]
*
* Slots 0–7: ECC private key, ECDH in clear, GenKey allowed
* SlotConfig = 0x2087 → low byte = 0x87, high byte = 0x20
*
* Slots 8–15: Public data, cleartext reads allowed, Always write
* SlotConfig = 0x000F → low byte = 0x0F, high byte = 0x00
*/
static const uint8_t TARGET_SLOT_CONFIG[32] = {
    /* Slot  0 */ SLOT_CONFIG_ECC_LO,  SLOT_CONFIG_ECC_HI,
    /* Slot  1 */ SLOT_CONFIG_ECC_LO,  SLOT_CONFIG_ECC_HI,
    /* Slot  2 */ SLOT_CONFIG_ECC_LO,  SLOT_CONFIG_ECC_HI,
    /* Slot  3 */ SLOT_CONFIG_ECC_LO,  SLOT_CONFIG_ECC_HI,
    /* Slot  4 */ SLOT_CONFIG_ECC_LO,  SLOT_CONFIG_ECC_HI,
    /* Slot  5 */ SLOT_CONFIG_ECC_LO,  SLOT_CONFIG_ECC_HI,
    /* Slot  6 */ SLOT_CONFIG_ECC_LO,  SLOT_CONFIG_ECC_HI,
    /* Slot  7 */ SLOT_CONFIG_ECC_LO,  SLOT_CONFIG_ECC_HI,
    /* Slot  8 */ SLOT_CONFIG_DATA_LO, SLOT_CONFIG_DATA_HI,
    /* Slot  9 */ SLOT_CONFIG_DATA_LO, SLOT_CONFIG_DATA_HI,
    /* Slot 10 */ SLOT_CONFIG_DATA_LO, SLOT_CONFIG_DATA_HI,
    /* Slot 11 */ SLOT_CONFIG_DATA_LO, SLOT_CONFIG_DATA_HI,
    /* Slot 12 */ SLOT_CONFIG_DATA_LO, SLOT_CONFIG_DATA_HI,
    /* Slot 13 */ SLOT_CONFIG_DATA_LO, SLOT_CONFIG_DATA_HI,
    /* Slot 14 */ SLOT_CONFIG_DATA_LO, SLOT_CONFIG_DATA_HI,
    /* Slot 15 */ SLOT_CONFIG_DATA_LO, SLOT_CONFIG_DATA_HI,
};

/*
* Target KeyConfig[0..15] – 32 bytes (2B per slot, little-endian in EEPROM).
* Array order: [slot_low_byte_0, slot_high_byte_0, ...]
*
* Slots 0–7: P-256 ECC, Private=1, PubInfo=1, Lockable=1
* KeyConfig = 0x0033 → Low Byte = 0x33, High Byte = 0x00
*
* Slots 8–15: Non-ECC, KeyType=111b=7
* KeyConfig = 0x001C → Low Byte = 0x1C, High Byte = 0x00
*/
static const uint8_t TARGET_KEY_CONFIG[32] = {
    /* Slot  0 */ KEY_CONFIG_ECC_LO,  KEY_CONFIG_ECC_HI,
    /* Slot  1 */ KEY_CONFIG_ECC_LO,  KEY_CONFIG_ECC_HI,
    /* Slot  2 */ KEY_CONFIG_ECC_LO,  KEY_CONFIG_ECC_HI,
    /* Slot  3 */ KEY_CONFIG_ECC_LO,  KEY_CONFIG_ECC_HI,
    /* Slot  4 */ KEY_CONFIG_ECC_LO,  KEY_CONFIG_ECC_HI,
    /* Slot  5 */ KEY_CONFIG_ECC_LO,  KEY_CONFIG_ECC_HI,
    /* Slot  6 */ KEY_CONFIG_ECC_LO,  KEY_CONFIG_ECC_HI,
    /* Slot  7 */ KEY_CONFIG_ECC_LO,  KEY_CONFIG_ECC_HI,
    /* Slot  8 */ KEY_CONFIG_DATA_LO, KEY_CONFIG_DATA_HI,
    /* Slot  9 */ KEY_CONFIG_DATA_LO, KEY_CONFIG_DATA_HI,
    /* Slot 10 */ KEY_CONFIG_DATA_LO, KEY_CONFIG_DATA_HI,
    /* Slot 11 */ KEY_CONFIG_DATA_LO, KEY_CONFIG_DATA_HI,
    /* Slot 12 */ KEY_CONFIG_DATA_LO, KEY_CONFIG_DATA_HI,
    /* Slot 13 */ KEY_CONFIG_DATA_LO, KEY_CONFIG_DATA_HI,
    /* Slot 14 */ KEY_CONFIG_DATA_LO, KEY_CONFIG_DATA_HI,
    /* Slot 15 */ KEY_CONFIG_DATA_LO, KEY_CONFIG_DATA_HI,
};

static const char *decode_write_config(uint8_t wc) 
{
    switch (wc) 
    {
        case 0x0: return "Always     (save always allowed)";
        case 0x1: return "PubInvalid (save when  zapis gdy klucz pub zinvalidowany)";
        case 0x2: return "Never      (save denied by Write cmd)";
        case 0x3: return "Never      (save denied by Write cmd)";
        case 0x4: return "Never      (bit15=1, save denied)";
        case 0x5: return "Never      (bit15=1, save denied)";
        case 0x6: return "Encrypt    (encrypted save + MAC)";
        case 0x7: return "Encrypt    (encrypted save + MAC)";
        case 0x8: return "Never      (bit15=1)";
        case 0x9: return "Never      (bit15=1)";
        case 0xA: return "Encrypt    (bit14=1, encrypted)";
        case 0xB: return "Encrypt    (bit14=1, encrypted)";
        case 0xC: return "Never      (bit15=1)";
        case 0xD: return "Never      (bit15=1)";
        case 0xE: return "Encrypt    (bit14=1, encrypted)";
        case 0xF: return "Encrypt    (bit14=1, encrypted)";
        default:  return "???";
    }
}

static const char *decode_key_type(uint8_t kt) 
{
    switch (kt) 
    {
        case 4:  return "P-256 ECC";
        case 6:  return "AES-128";
        case 7:  return "Nie-ECC (dane)";
        default: return "RFU";
    }
}

static void print_hex_line(const char *label, const uint8_t *data, size_t len) 
{
    printf("  %-20s:", label);
    for (size_t i = 0; i < len; i++) printf(" %02X", data[i]);
    printf("\n");
}

ATCA_STATUS atecc608a_read_config(uint8_t out[CONFIG_ZONE_SIZE]) 
{
    ATCA_STATUS status = atcab_read_config_zone(out);
    if (status != ATCA_SUCCESS) 
    {
        printf("[CONFIG] ERROR when reading config zone: 0x%02X\n", status);
    }
    return status;
}

void atecc608a_print_config(const uint8_t cfg[CONFIG_ZONE_SIZE]) 
{
    printf("\n");
    printf("============================================================\n");
    printf(" ATECC608A – Configuration Zone Inspection (128 bytes)\n");
    printf("============================================================\n\n");

    printf("[ Identification ]\n");
    printf("  Serial Number (SN[0:8])  : %02X%02X%02X%02X %02X%02X%02X%02X %02X\n",
           cfg[0], cfg[1], cfg[2], cfg[3],
           cfg[8], cfg[9], cfg[10], cfg[11], cfg[12]);
    printf("  RevNum                    : %02X %02X %02X %02X\n",
           cfg[4], cfg[5], cfg[6], cfg[7]);

    printf("\n[ Interface ]\n");
    uint8_t i2c_en   = cfg[CONFIG_OFFSET_I2C_EN];
    uint8_t i2c_addr = cfg[CONFIG_OFFSET_I2C_ADDR];
    printf("  I2C_Enable  [14]          : 0x%02X  (%s)\n",
           i2c_en, (i2c_en & 0x01) ? "I2C" : "Single-Wire");
    printf("  I2C_Address [16]          : 0x%02X  (7-bit: 0x%02X)\n",
           i2c_addr, (i2c_addr >> 1) & 0x7F);

    printf("\n[ Device Mode ]\n");
    uint8_t otp_mode  = cfg[CONFIG_OFFSET_OTP_MODE];
    uint8_t chip_mode = cfg[CONFIG_OFFSET_CHIP_MODE];
    const char *otp_str = (otp_mode == OTP_MODE_READ_ONLY)   ? "Read-Only (0xAA)" :
                          (otp_mode == OTP_MODE_CONSUMPTION)  ? "Consumption (0x55)" :
                          "Unknown";
    printf("  OTPmode     [18]          : 0x%02X  (%s)\n", otp_mode, otp_str);
    printf("  ChipMode    [19]          : 0x%02X\n", chip_mode);
    printf("    Bit2 Watchdog           : %s\n",
           (chip_mode & 0x04) ? "10.0s" : "1.3s (recommended)");
    printf("    Bit1 TTLenable          : %s\n",
           (chip_mode & 0x02) ? "VCC-referenced" : "Fixed reference");
    printf("    Bit0 SelectorMode       : %s\n",
           (chip_mode & 0x01) ? "One-time write" : "Always writeable");

    printf("\n[ Block Status ]\n");
    uint8_t lock_val = cfg[CONFIG_OFFSET_LOCK_VAL];
    uint8_t lock_cfg = cfg[CONFIG_OFFSET_LOCK_CFG];
    bool cfg_locked  = (lock_cfg != ZONE_UNLOCKED);
    bool data_locked = (lock_val != ZONE_UNLOCKED);
    printf("  LockConfig  [87]          : 0x%02X  -> Config zone: %s\n",
           lock_cfg, cfg_locked ? "LOCKED" : "UNLOCKED");
    printf("  LockValue   [86]          : 0x%02X  -> Data/OTP zone: %s\n",
           lock_val, data_locked ? "LOCKED" : "UNLOCKED");

    uint16_t slot_locked = (uint16_t)cfg[CONFIG_OFFSET_SLOT_LOCK] |
                           ((uint16_t)cfg[CONFIG_OFFSET_SLOT_LOCK + 1] << 8);
    printf("  SlotLocked  [88-89]       : 0x%04X\n", slot_locked);
    printf("    (bit=0 means slot LOCKED)\n");
    printf("    Slots: ");
    for (int s = 0; s < 16; s++) {
        bool locked_slot = !((slot_locked >> s) & 0x01);
        if (locked_slot) printf("%d* ", s);
        else             printf("%d  ", s);
    }
    printf("\n    (* = individually locked)\n");

    printf("\n[ SlotConfig (bajty 20-51) ]\n");
    printf("  %-6s %-10s %-12s %-8s %-8s %-8s %-8s %-8s %-8s %-8s\n",
           "Slot", "Value", "WriteConfig", "WriteKey",
           "IsSecret", "EncRead", "LimUse", "NoMac", "ECDH", "ExtSign");
    printf("  %s\n", "--------------------------------------------------------------"
                     "---------------------------------");

    for (int s = 0; s < 16; s++) 
    {
        uint8_t lo = cfg[CONFIG_OFFSET_SLOT_CFG + s * 2];
        uint8_t hi = cfg[CONFIG_OFFSET_SLOT_CFG + s * 2 + 1];
        uint16_t sc = (uint16_t)lo | ((uint16_t)hi << 8);

        uint8_t write_cfg = (sc >> 12) & 0x0F;
        uint8_t write_key = (sc >> 8)  & 0x0F;
        uint8_t is_secret = (sc >> 7)  & 0x01;
        uint8_t enc_read  = (sc >> 6)  & 0x01;
        uint8_t lim_use   = (sc >> 5)  & 0x01;
        uint8_t no_mac    = (sc >> 4)  & 0x01;
        uint8_t rk = sc & 0x0F;
        uint8_t ecdh_ok   = (rk >> 2) & 0x01;
        uint8_t ecdh_enc  = (rk >> 3) & 0x01;
        uint8_t ext_sign  = rk & 0x01;

        printf("  %-5d  0x%04X   %-3X            %-8d %-8d %-8d %-8d %-8d ",
               s, sc, write_cfg, write_key, is_secret, enc_read, lim_use, no_mac);
        if (s <= 7) 
        {
            printf("%s%-3s  %s\n",
                   ecdh_ok  ? "YES " : "NO ",
                   ecdh_enc ? "(->slot)" : "(clear)",
                   ext_sign ? "YES" : "NO");
        } 
        else 
        {
            printf("N/D          N/D\n");
        }
    }

    printf("\n[ KeyConfig (bajty 96-127) ]\n");
    printf("  %-6s %-10s %-16s %-10s %-10s %-10s %-10s %-10s\n",
           "Slot", "Value", "KeyType", "Private",
           "PubInfo", "Lockable", "ReqRand", "ReqAuth");
    printf("  %s\n", "--------------------------------------------------------------"
                     "------------------");

    for (int s = 0; s < 16; s++) 
    {
        uint8_t lo = cfg[CONFIG_OFFSET_KEY_CFG + s * 2];
        uint8_t hi = cfg[CONFIG_OFFSET_KEY_CFG + s * 2 + 1];
        uint16_t kc = (uint16_t)lo | ((uint16_t)hi << 8);

        uint8_t priv      = kc & 0x01;
        uint8_t pub_info  = (kc >> 1) & 0x01;
        uint8_t key_type  = (kc >> 2) & 0x07;
        uint8_t lockable  = (kc >> 5) & 0x01;
        uint8_t req_rand  = (kc >> 6) & 0x01;
        uint8_t req_auth  = (kc >> 7) & 0x01;

        printf("  %-5d  0x%04X   %-16s %-10s %-10s %-10s %-10s %-10s\n",
               s, kc,
               decode_key_type(key_type),
               priv     ? "YES" : "NO",
               pub_info ? "YES" : "NO",
               lockable ? "YES" : "NO",
               req_rand ? "YES" : "NO",
               req_auth ? "YES" : "NO");
    }

    printf("\n[ Full hex dump (128 bytes) ]\n");
    for (int i = 0; i < 128; i++) 
    {
        if (i % 16 == 0) printf("  [%02X] ", i);
        printf("%02X ", cfg[i]);
        if (i % 16 == 15) printf("\n");
    }
    printf("\n============================================================\n\n");
}

void atecc608a_print_lock_status(const uint8_t cfg[CONFIG_ZONE_SIZE]) 
{
    uint8_t lock_val = cfg[CONFIG_OFFSET_LOCK_VAL];
    uint8_t lock_cfg = cfg[CONFIG_OFFSET_LOCK_CFG];
    uint16_t slot_locked = (uint16_t)cfg[CONFIG_OFFSET_SLOT_LOCK] |
                           ((uint16_t)cfg[CONFIG_OFFSET_SLOT_LOCK + 1] << 8);

    printf("\n[ Lock Status ]\n");
    printf("  Config zone : %s (LockConfig=0x%02X)\n",
           (lock_cfg != ZONE_UNLOCKED) ? "LOCKED" : "UNLOCKED", lock_cfg);
    printf("  Data/OTP    : %s (LockValue=0x%02X)\n",
           (lock_val != ZONE_UNLOCKED) ? "LOCKED" : "UNLOCKED", lock_val);

    for (int s = 0; s < 16; s++) 
    {
        bool slot_lk = !((slot_locked >> s) & 0x01);
        if (slot_lk) 
        {
            printf("  Slot %2d     : LOCKED individually\n", s);
        }
    }
}

ATCA_STATUS atecc608a_write_config(void) 
{
    ATCA_STATUS status;
    uint8_t cfg[CONFIG_ZONE_SIZE];

    printf("\n[CONFIG] Saving target configuration...\n");

    status = atcab_read_config_zone(cfg);
    if (status != ATCA_SUCCESS) 
    {
        printf("[CONFIG] ERROR: cannot read config zone: 0x%02X\n", status);
        return status;
    }

    if (cfg[CONFIG_OFFSET_LOCK_CFG] != ZONE_UNLOCKED) 
    {
        printf("[CONFIG] ERROR: config zone is already LOCKED (LockConfig=0x%02X).\n",
               cfg[CONFIG_OFFSET_LOCK_CFG]);
        printf("         Cannot modify locked config zone.\n");
        return ATCA_NOT_LOCKED;
    }

    printf("[CONFIG] Config zone unlocked – can be written.\n");

    printf("[CONFIG] Writing SlotConfig[0..15] (bytes 20-51)...\n");
    status = atcab_write_bytes_zone(ATCA_ZONE_CONFIG, 0,
                                    CONFIG_OFFSET_SLOT_CFG,
                                    TARGET_SLOT_CONFIG,
                                    sizeof(TARGET_SLOT_CONFIG));
    if (status != ATCA_SUCCESS) 
    {
        printf("[CONFIG] ERROR: failed to write SlotConfig: 0x%02X\n", status);
        return status;
    }
    printf("[CONFIG] SlotConfig: OK\n");

    printf("[CONFIG] Writing KeyConfig[0..15] (bytes 96-127)...\n");
    status = atcab_write_bytes_zone(ATCA_ZONE_CONFIG, 0,
                                    CONFIG_OFFSET_KEY_CFG,
                                    TARGET_KEY_CONFIG,
                                    sizeof(TARGET_KEY_CONFIG));
    if (status != ATCA_SUCCESS) 
    {
        printf("[CONFIG] ERROR: failed to write KeyConfig: 0x%02X\n", status);
        return status;
    }
    printf("[CONFIG] KeyConfig: OK\n");
    
    printf("[CONFIG] Setting OTPmode = Read-Only (byte 18)...\n");
    uint8_t word16_19[4];
    status = atcab_read_bytes_zone(ATCA_ZONE_CONFIG, 0, 16, word16_19, 4);
    if (status != ATCA_SUCCESS) 
    {
        printf("[CONFIG] ERROR: failed to read bytes 16-19: 0x%02X\n", status);
        return status;
    }
    word16_19[2] = OTP_MODE_READ_ONLY;
    status = atcab_write_bytes_zone(ATCA_ZONE_CONFIG, 0, 16, word16_19, 4);
    if (status != ATCA_SUCCESS) 
    {
        printf("[CONFIG] ERROR: failed to write OTPmode: 0x%02X\n", status);
        return status;
    }
    printf("[CONFIG] OTPmode: OK\n");

    printf("[CONFIG] Writing configuration: COMPLETED SUCCESSFULLY.\n");
    printf("[CONFIG] Run atecc608a_verify_config() before locking!\n");
    return ATCA_SUCCESS;
}

ATCA_STATUS atecc608a_verify_config(void) 
{
    ATCA_STATUS status;
    uint8_t cfg[CONFIG_ZONE_SIZE];
    bool ok = true;

    printf("\n[VERIFY] Verifying chip configuration...\n");

    status = atcab_read_config_zone(cfg);
    if (status != ATCA_SUCCESS) 
    {
        printf("[VERIFY] ERROR: failed to read config: 0x%02X\n", status);
        return status;
    }

    for (int s = 0; s < 16; s++) 
    {
        uint8_t actual_lo = cfg[CONFIG_OFFSET_SLOT_CFG + s * 2];
        uint8_t actual_hi = cfg[CONFIG_OFFSET_SLOT_CFG + s * 2 + 1];
        uint8_t target_lo = TARGET_SLOT_CONFIG[s * 2];
        uint8_t target_hi = TARGET_SLOT_CONFIG[s * 2 + 1];

        if (actual_lo != target_lo || actual_hi != target_hi) 
        {
            uint16_t actual = (uint16_t)actual_lo | ((uint16_t)actual_hi << 8);
            uint16_t target = (uint16_t)target_lo | ((uint16_t)target_hi << 8);
            printf("[VERIFY]   MISMATCH SlotConfig[%d]: got 0x%04X, expected 0x%04X\n",
                   s, actual, target);
            printf("[VERIFY]     (raw bytes: got [LO=0x%02X HI=0x%02X],"
                   " expected [LO=0x%02X HI=0x%02X])\n",
                   actual_lo, actual_hi, target_lo, target_hi);
            ok = false;
        }
    }

    if (ok) printf("[VERIFY]   SlotConfig: OK\n");

    bool kc_ok = true;
    printf("[VERIFY] KeyConfig[0..15]...\n");
    for (int s = 0; s < 16; s++) 
    {
        uint8_t actual_lo = cfg[CONFIG_OFFSET_KEY_CFG + s * 2];
        uint8_t actual_hi = cfg[CONFIG_OFFSET_KEY_CFG + s * 2 + 1];
        uint8_t target_lo = TARGET_KEY_CONFIG[s * 2];
        uint8_t target_hi = TARGET_KEY_CONFIG[s * 2 + 1];

        if (actual_lo != target_lo || actual_hi != target_hi) 
        {
            uint16_t actual = (uint16_t)actual_lo | ((uint16_t)actual_hi << 8);
            uint16_t target = (uint16_t)target_lo | ((uint16_t)target_hi << 8);
            printf("[VERIFY]   MISMATCH KeyConfig[%d]: got 0x%04X, expected 0x%04X\n",
                   s, actual, target);
            printf("[VERIFY]     (raw bytes: got [LO=0x%02X HI=0x%02X],"
                   " expected [LO=0x%02X HI=0x%02X])\n",
                   actual_lo, actual_hi, target_lo, target_hi);
            kc_ok = false;
            ok = false;
        }
    }

    if (kc_ok) printf("[VERIFY]   KeyConfig: OK\n");

    uint8_t otp_mode = cfg[CONFIG_OFFSET_OTP_MODE];
    if (otp_mode != OTP_MODE_READ_ONLY) 
    {
        printf("[VERIFY]   OTPmode MISMATCH: got 0x%02X, expected 0x%02X (Read-Only)\n",
               otp_mode, OTP_MODE_READ_ONLY);
        ok = false;
    } 
    else 
    {
        printf("[VERIFY]   OTPmode: OK (0xAA = Read-Only)\n");
    }

    if (ok) 
    {
        printf("[VERIFY] RESULT: OK – configuration matches the target.\n");
        printf("[VERIFY] You can now call atecc608a_lock_config_zone(true).\n");
        return ATCA_SUCCESS;
    } 
    else 
    {
        printf("[VERIFY] RESULT: FAILED – configuration does not match the target. DO NOT lock!\n");
        return ATCA_GEN_FAIL;
    }
}

ATCA_STATUS atecc608a_lock_config_zone(bool confirm) 
{
    if (!confirm) 
    {
        printf("[LOCK] Call with confirm=true to confirm. IRREVERSIBLE!\n");
        return ATCA_GEN_FAIL;
    }

    printf("\n[LOCK] !!! LOCKING CONFIG ZONE – IRREVERSIBLE !!!\n");

    ATCA_STATUS verify_status = atecc608a_verify_config();
    if (verify_status != ATCA_SUCCESS)
    {
        printf("[LOCK] ABANDONED: verification of configuration failed.\n");
        printf("[LOCK] First, fix the configuration using atecc608a_write_config().\n");
        return ATCA_GEN_FAIL;
    }

    ATCA_STATUS status = atcab_lock_config_zone();
    if (status != ATCA_SUCCESS) 
    {
        printf("[LOCK] ERROR locking config zone: 0x%02X\n", status);
        printf("[LOCK] Possible reasons: CRC mismatch, chip already locked.\n");
        return status;
    }

    printf("[LOCK] Config zone LOCKED successfully.\n");
    printf("[LOCK] Next step: generate keys (atcab_genkey) and then\n");
    printf("[LOCK] call atecc608a_lock_data_zone(true).\n");
    return ATCA_SUCCESS;
}

ATCA_STATUS atecc608a_lock_data_zone(bool confirm) 
{
    if (!confirm) 
    {
        printf("[LOCK] Call with confirm=true to confirm. IRREVERSIBLE!\n");
        return ATCA_GEN_FAIL;
    }

    uint8_t cfg[CONFIG_ZONE_SIZE];
    ATCA_STATUS status = atcab_read_config_zone(cfg);
    if (status != ATCA_SUCCESS) 
    {
        printf("[LOCK] ERROR reading config zone: 0x%02X\n", status);
        return status;
    }

    if (cfg[CONFIG_OFFSET_LOCK_CFG] == ZONE_UNLOCKED) 
    {
        printf("[LOCK] ERROR: Config zone must be locked before locking data zone.\n");
        return ATCA_GEN_FAIL;
    }

    if (cfg[CONFIG_OFFSET_LOCK_VAL] != ZONE_UNLOCKED) 
    {
        printf("[LOCK] ERROR: Data/OTP zone is already locked.\n");
        return ATCA_NOT_LOCKED;
    }

    printf("\n[LOCK] !!! LOCKING DATA/OTP ZONE – IRREVERSIBLE !!!\n");
    printf("[LOCK] After this step, ECC slots will be ready for use.\n");

    status = atcab_lock_data_zone();
    if (status != ATCA_SUCCESS) 
    {
        printf("[LOCK] ERROR locking data zone: 0x%02X\n", status);
        return status;
    }

    printf("[LOCK] Data/OTP zone LOCKED successfully.\n");
    printf("[LOCK] Device ready. You can generate keys via atcab_genkey().\n");
    return ATCA_SUCCESS;
}

ATCA_STATUS atecc608a_check_key_slot(uint8_t slot, uint8_t out_pubkey[64]) 
{
    if (slot > PICO_CRYPT_ECC_SLOT_MAX) 
    {
        printf("[KEY] Slot %d out of ECC range (0-%d).\n",
               slot, PICO_CRYPT_ECC_SLOT_MAX);
        return ATCA_BAD_PARAM;
    }

    uint8_t pubkey_buf[64];

    ATCA_STATUS status = atcab_get_pubkey(slot, pubkey_buf);

    if (status == ATCA_SUCCESS) 
    {
        if (out_pubkey != NULL) 
        {
            memcpy(out_pubkey, pubkey_buf, 64);
        }
        return ATCA_SUCCESS;
    } 
    else 
    {
        /* Slot pusty lub błąd */
        return status;
    }
}

void atecc608a_print_all_keys(void) 
{
    printf("\n[ ECC keys status (slots 0-%d) ]\n", PICO_CRYPT_ECC_SLOT_MAX);
    printf("  %-6s %-12s %-16s\n", "Slot", "Status", "Fingerprint (SHA256[:8])");
    printf("  %s\n", "--------------------------------------------");

    for (uint8_t s = 0; s <= PICO_CRYPT_ECC_SLOT_MAX; s++) 
    {
        uint8_t pubkey[64];
        ATCA_STATUS status = atecc608a_check_key_slot(s, pubkey);

        if (status == ATCA_SUCCESS) 
        {
            uint8_t digest[32];
            ATCA_STATUS sha_st = atcab_sha(64, pubkey, digest);
            if (sha_st == ATCA_SUCCESS) 
            {
                printf("  %-5d  %-12s %02X%02X%02X%02X%02X%02X%02X%02X%s\n",
                       s, "EXISTS",
                       digest[0], digest[1], digest[2], digest[3],
                       digest[4], digest[5], digest[6], digest[7],
                       (s == 0) ? "  (default)" : "");
            } 
            else 
            {
                printf("  %-5d  %-12s (SHA error: 0x%02X)\n", s, "EXISTS", sha_st);
            }
        } 
        else 
        {
            printf("  %-5d  %-12s\n", s, "EMPTY");
        }
    }
    printf("\n");
}
