/**
* Definition of the ATECC608A configuration zone for the pico-crypt project.
*
* SLOT LAYOUT (slots 0–7 are user-defined ECC keys):
*
* Slot Size Purpose ECDH GenKey Sign.
* ---- ------- ------------------------------ ---- ------ -----
* 0 36B ECC P-256 Key #0 (default) YES YES YES
* 1 36B ECC P-256 Key #1 YES YES YES
* 2 36B ECC P-256 Key #2 YES YES YES
* 3 36B ECC P-256 Key #3 YES YES YES
* 4 36B ECC P-256 Key #4 YES YES YES
* 5 36B ECC P-256 Key #5 YES YES YES
* 6 36B ECC P-256 Key #6 YES YES YES
* 7 36B ECC P-256 Key #7 YES YES YES
* 8 416B General Data (public certificates / pub keys)
* 9 72B General Data (reserve)
* 10 72B General Data (reserve)
* 11 72B General Data (reserve)
* 12 72B General Data (reserve)
* 13 72B General Data (reserve)
* 14 72B General Data (reserve)
* 15 72B General Data (reserve)
*
* SLOT CONFIGURATION 0–7 (ECC private key, ECDH output in clear):
*
* SlotConfig (2 bytes, little-endian in config zone):
* Bit 0 (ReadKey[0]) = 1 → External signatures (Sign from external message) ENABLED
* Bit 1 (ReadKey[1]) = 1 → Internal signatures (Sign from GenDig/GenKey) ENABLED
* Bit 2 (ReadKey[2]) = 1 → ECDH PERMITTED ← key
* Bit 3 (ReadKey[3]) = 0 → ECDH output IN CLEAR (not for slot N+1) ← key
* Bit 4 (NoMac) = 0 → Key can be used with MAC/HMAC
* Bit 5 (LimitedUse) = 0 → Unlimited uses
* Bit 6 (EncryptRead) = 0 → Not applicable (private key – cannot be read)
* Bit 7 (IsSecret) = 1 → Content SECRET (required for ECC private key)
* Bits 11-8 (WriteKey) = 0 → WriteKey = slot 0 (reference, not used)
* Bits 15-12 (WriteConfig) = 0010b = 0x2 → Never (Write command disabled)
* GenKey CAN write (bit 13 = 1)
*
* SlotConfig value: 0b 0010 0000 1000 0111 = 0x2087
* Low byte (config[20 + slot*2]) = 0x87
* High byte (config[20 + slot*2+1]) = 0x20
*
* KeyConfig (2 bytes):
* Bit 0 (Private) = 1 → Contains ECC private key
* Bit 1 (PubInfo) = 1 → Public key always accessible via GenKey(Public)
* Bits 4-2 (KeyType) = 100b = 4 → P-256 NIST ECC key
* Bit 5 (Lockable) = 1 → Slots can be individually locked.
* Bit 6 (ReqRandom) = 0 → No random nonce required.
* Bit 7 (ReqAuth) = 0 → No authorization required before use.
* Bits 11-8 (AuthKey) = 0 → Not used (ReqAuth=0)
* Bit 12 (IntrusionDisable) = 0 → Independent of IntrusionLatch.
* Bit 13 (RFU) = 0 → Reserved.
* Bits 15-14 (X509id) = 00 → No X.509 format restriction.
*
* KeyConfig value: 0b 0000 0000 0010 0111 = 0x0033
* Low byte (config[96 + slot*2]) = 0x33
* High Byte (config[96 + slot*2+1]) = 0x00
*
* SLOT 8–15 CONFIGURATION (public data, no private keys):
*
* SlotConfig: 0x000F
* Bits 3-0 (ReadKey) = 0xF → ReadKey=15 (avoids CheckMac/Copy, per datasheet warning)
* Bit 4 (NoMac) = 0 → Allowed with MAC/HMAC
* Bit 5 (LimitedUse) = 0 → NO usage limit (not associated with Counter<0>)
* Bit 6 (EncryptRead) = 0 → Cleartext reads allowed
* Bit 7 (IsSecret) = 0 → PUBLIC data – cleartext reads allowed
* (IsSecret=0, EncryptRead=0) → Table 2-7: Reads always permitted)
* Bits 11-8 (WriteKey) = 0 → Not used with WriteConfig=Always
* Bits 15-12 (WriteConfig) = 0000b → Always (always writeable)
*
* SlotConfig Value: 0b 0000 0000 0000 1111 = 0x000F
* Low Byte = 0x0F, High Byte = 0x00
*
* KeyConfig: 0x001C
* Bit 0 (Private) = 0 → Non-ECC private key
* Bit 1 (PubInfo) = 0 → Not applicable
* Bits 4-2 (KeyType) = 111b = 7 → Non-ECC key
* Bit 5 (Lockable) = 0 → Slot cannot be individually locked
*
* KeyConfig Value: 0b 0000 0000 0001 1100 = 0x001C
* Low Byte = 0x1C, High Byte = 0x00
*/

#pragma once
#include <stdint.h>
#include <stdbool.h>
#include "cryptoauthlib.h"

/* =========================================================================
 * CONFIGURATION CONSTANTS
 * ========================================================================= */

#define PICO_CRYPT_ECC_SLOT_MIN    0
#define PICO_CRYPT_ECC_SLOT_MAX    7
#define PICO_CRYPT_ECC_SLOT_COUNT  8    /* slots 0–7: ECC keys for user */
#define PICO_CRYPT_DATA_SLOT_MIN   8
#define PICO_CRYPT_DATA_SLOT_MAX   15

/*
* SlotConfig for ECC slots (0–7): 0x2087
*
* Decoding bits (datasheet Table 2-6):
* For a private key, the ReadKey[3:0] slot has a different meaning than for data:
* Bit 0: External signature = 1
* Bit 1: Internal signature = 1
* Bit 2: ECDH permitted = 1
* Bit 3: ECDH output in clear = 0
* Bit 4: NoMac = 0
* Bit 5: LimitedUse = 0
* Bit 6: EncryptRead = 0 (not applicable to private key)
* Bit 7: IsSecret = 1 (required for private key!)
* Bits 11-8: WriteKey = 0
* Bits 15-12: WriteConfig = 0010 → bit 13=1: GenKey can write
* bit 12=0: Write command = Never
*/
#define SLOT_CONFIG_ECC_LO   0x87u   /* low byte  SlotConfig[7:0]  */
#define SLOT_CONFIG_ECC_HI   0x20u   /* high byte SlotConfig[15:8] */
#define SLOT_CONFIG_ECC_WORD 0x2087u

/*
* KeyConfig for ECC slots (0–7): 0x0033
*
* Decoding (datasheet Table 2-12):
* Bit 0: Private = 1 (ECC private key)
* Bit 1: PubInfo = 1 (GenKey(Public) always allowed)
* Bits 4-2: KeyType = 100b = 4 (P-256)
* Bit 5: Lockable = 1 (individual lock via Lock command)
* Bit 6: ReqRandom = 0
* Bit 7: ReqAuth = 0
* Bits 15-8: = 0
*/
#define KEY_CONFIG_ECC_LO    0x33u   /* low byte  KeyConfig[7:0]  */
#define KEY_CONFIG_ECC_HI    0x00u   /* high byte KeyConfig[15:8] */
#define KEY_CONFIG_ECC_WORD  0x0033u

/*
* SlotConfig for data slots (8–15): 0x000F
*
* Bit 7: IsSecret = 0 → public data, cleartext reads ALLOWED (Table 2-7)
* Bit 5: LimitedUse = 0 → unlimited use, not associated with Counter<0>
* Bit 6: EncryptRead = 0 → no read encryption
* Bits 3-0: ReadKey = 0xF → avoid ReadKey=0 (CheckMac/Copy, per datasheet warning)
* Bits 11-8: WriteKey = 0 → not used with WriteConfig=Always
* Bits 15-12: WriteConfig = 0000 = Always → free writes always allowed
*/
#define SLOT_CONFIG_DATA_LO  0x0Fu
#define SLOT_CONFIG_DATA_HI  0x00u
#define SLOT_CONFIG_DATA_WORD 0x000Fu

/*
* KeyConfig for data slots (8–15): 0x001C
*
* Bit 0: Private = 0
* Bit 1: PubInfo = 0
* Bits 4-2: KeyType = 111b = 7 (Not an ECC key – required for non-ECC)
* Bit 5: Lockable = 0
*/
#define KEY_CONFIG_DATA_LO   0x1Cu
#define KEY_CONFIG_DATA_HI   0x00u
#define KEY_CONFIG_DATA_WORD 0x001Cu

/* Byte positions in config zone (128 bytes total) */
#define CONFIG_ZONE_SIZE        128
#define CONFIG_OFFSET_SN0       0    /* SN[0:3] – 4 bytes (RO) */
#define CONFIG_OFFSET_REVNUM    4    /* RevNum – 4 bytes (RO) */
#define CONFIG_OFFSET_SN4       8    /* SN[4:8] – 5 bytes (RO) */
#define CONFIG_OFFSET_I2C_EN    14   /* I2C_Enable */
#define CONFIG_OFFSET_I2C_ADDR  16   /* I2C_Address */
#define CONFIG_OFFSET_OTP_MODE  18   /* OTPmode */
#define CONFIG_OFFSET_CHIP_MODE 19   /* ChipMode */
#define CONFIG_OFFSET_SLOT_CFG  20   /* SlotConfig[0..15] – 32 bytes (2B per slot) */
#define CONFIG_OFFSET_COUNTER0  52   /* Counter<0> – 8 bytes */
#define CONFIG_OFFSET_COUNTER1  60   /* Counter<1> – 8 bytes */
#define CONFIG_OFFSET_LAST_KEY  68   /* LastKeyUse – 16 bytes */
#define CONFIG_OFFSET_USER_XTRA 84   /* UserExtra */
#define CONFIG_OFFSET_SELECTOR  85   /* Selector */
#define CONFIG_OFFSET_LOCK_VAL  86   /* LockValue */
#define CONFIG_OFFSET_LOCK_CFG  87   /* LockConfig */
#define CONFIG_OFFSET_SLOT_LOCK 88   /* SlotLocked – 2 bytes */
#define CONFIG_OFFSET_X509      92   /* X509format – 4 bytes */
#define CONFIG_OFFSET_KEY_CFG   96   /* KeyConfig[0..15] – 32 bytes (2B per slot) */

/* Values for LockConfig / LockValue */
#define ZONE_UNLOCKED  0x55u
#define ZONE_LOCKED    0x00u

/* OTPmode */
#define OTP_MODE_READ_ONLY   0xAAu
#define OTP_MODE_CONSUMPTION 0x55u

/* ============================================================================ 
* Bytes 52–95: Counter, LastKeyUse, UserExtra, Selector, LockValue, LockConfig,
* SlotLocked, RFU, X509format – use default values ​​or 0.
* Bytes 96–127: KeyConfig[0..15] – defined below.
*
* NOTE: We don't write the entire config zone at once – we use atcab_write_bytes_zone()
* for specific bytes. Bytes 0–15 and bytes managed by Microchip
* (RevNum, SN) are read-only. 
* ============================================================================ */

/* Full config zone to verify (128B).
* Bytes 0–15 are filled with atcab_read_config_zone() – placeholder 0x00 here.
* Writable bytes defined below. */
typedef struct {
    uint8_t bytes[CONFIG_ZONE_SIZE];
} config_zone_t;

/* =========================================================================
 * FUNCTION DECLARATIONS
 * ========================================================================= */

/**
* atecc608a_read_config()
* Reads the full configuration zone (128B) into the out buffer.
* Safe to call BEFORE locking.
*/
ATCA_STATUS atecc608a_read_config(uint8_t out[CONFIG_ZONE_SIZE]);

/**
* atecc608a_print_config()
* Prints a detailed interpretation of the config zone via USB CDC (printf).
* Shows each slot with comments: key type, permissions, status.
*/
void atecc608a_print_config(const uint8_t cfg[CONFIG_ZONE_SIZE]);

/**
* atecc608a_write_config()
* Writes the target configuration to the chip.
*
* CONDITION: config zone MUST be unlocked (LockConfig == 0x55).
* Function:
* 1. Checks if the config zone is unlocked.
* 2. Writes SlotConfig[0..15] (bytes 20–51).
* 3. Writes KeyConfig[0..15] (bytes 96–127).
* 4. Sets OTPmode = Read-Only (byte 18).
* 5. Leaves bytes 0–15 untouched (RO), does not lock.
*
* Returns ATCA_SUCCESS if successful, ATCA_NOT_LOCKED if config is already locked.
*/
ATCA_STATUS atecc608a_write_config(void);

/**
* atecc608a_verify_config()
* Verifies that the current chip configuration MATCHES the target one.
* Compares bytes 18–19, 20–51, 96–127.
*
* Returns ATCA_SUCCESS if the configuration is correct.
* Returns ATCA_GEN_FAIL if there is a mismatch (displays which bytes).
*/
ATCA_STATUS atecc608a_verify_config(void);

/**
* atecc608a_lock_config_zone()
* Locks the config zone. IRREVERSIBLE.
*
* CONDITION: atecc608a_verify_config() must return ATCA_SUCCESS BEFORE being called.
* This function requires confirmation (call with confirm=true).
*
* After execution: LockConfig == 0x00, the config zone will never be modified.
*/
ATCA_STATUS atecc608a_lock_config_zone(bool confirm);

/**
* atecc608a_lock_data_zone()
* Locks the Data and OTP zone. IRREVERSIBLE.
*
* CONDITION: config zone must be LOCKED.
* This function requires confirmation (call with confirm=true).
*/
ATCA_STATUS atecc608a_lock_data_zone(bool confirm);

/**
* atecc608a_print_lock_status()
* Prints the current lock status:
* - LockConfig (whether the config zone is locked)
* - LockValue (whether the data/OTP zone is locked)
* - SlotLocked[0..15]
*/
void atecc608a_print_lock_status(const uint8_t cfg[CONFIG_ZONE_SIZE]);

/**
* atecc608a_check_key_slot()
* Checks if an ECC key exists in the given slot (0–7).
* Uses atcab_get_pubkey() – success = key exists.
*
* out_pubkey: if != NULL and key exists, padded with 64 bytes (X||Y).
* Returns ATCA_SUCCESS if key exists.
*/
ATCA_STATUS atecc608a_check_key_slot(uint8_t slot, uint8_t out_pubkey[64]);

/**
* atecc608a_print_all_keys()
* Checks slots 0–7 and prints which ones have keys (fingerprint SHA256[:8]).
* Requires a locked data zone (after Lock).
*/
void atecc608a_print_all_keys(void);
