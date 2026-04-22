/**
 * atecc608a_config.c
 *
 * Implementacja funkcji konfiguracji strefy config ATECC608A.
 *
 * Kolejność użycia (safe workflow):
 *   1. atecc608a_read_config()    → odczytaj co jest teraz
 *   2. atecc608a_print_config()   → sprawdź wizualnie
 *   3. atecc608a_write_config()   → zapisz docelową konfigurację
 *   4. atecc608a_verify_config()  → upewnij się że zapis się powiódł
 *   5. atecc608a_print_config()   → ponowna inspekcja
 *   6. atecc608a_lock_config_zone(true)  ← NIEODWRACALNE
 *   7. atecc608a_lock_data_zone(true)    ← NIEODWRACALNE (po wgraniu kluczy)
 */

#include "atecc608a_config.h"
#include <stdio.h>
#include <string.h>
#include "atca_basic.h"

/* =========================================================================
 * TABELE DOCELOWYCH WARTOŚCI
 * =========================================================================
 *
 * ENDIANNESS – KLUCZOWA KWESTIA:
 *
 * Datasheet (sekcja 4.1) stwierdza:
 *   "16 bit (2 byte) integers, typically Param2, SlotConfig or KeyConfig,
 *    appear on the bus least-significant byte first."
 *
 * To znaczy że w EEPROM (i w buforze zwracanym przez atcab_read_config_zone):
 *   cfg[20] = bajt NISKI  (bits 7:0)  SlotConfig[0]
 *   cfg[21] = bajt WYSOKI (bits 15:8) SlotConfig[0]
 *   cfg[22] = bajt NISKI  SlotConfig[1]
 *   cfg[23] = bajt WYSOKI SlotConfig[1]
 *   ...
 *
 * Tablice TARGET_* układamy w tej samej kolejności: [LO, HI, LO, HI, ...].
 * atcab_write_bytes_zone() przekazuje bajty chipowi bez żadnej konwersji –
 * chipowi dostarczamy bajty dokładnie tak jak leżą w EEPROM.
 *
 * Przy odczycie i dekodowaniu składamy uint16_t przez:
 *   uint16_t sc = (uint16_t)lo | ((uint16_t)hi << 8);
 * co odtwarza pełną wartość z prawidłowym przypisaniem bitów do pól.
 * ========================================================================= */

/*
 * Docelowe SlotConfig[0..15] – 32 bajty (2B na slot, little-endian w EEPROM).
 * Kolejność w tablicy: [bajt_niski_slotu0, bajt_wysoki_slotu0, bajt_niski_slotu1, ...]
 *
 * Sloty 0–7:  ECC private key, ECDH in clear, GenKey allowed
 *   SlotConfig = 0x2087  →  bajt niski = 0x87, bajt wysoki = 0x20
 *
 * Sloty 8–15: Dane publiczne, cleartext reads dozwolone, Always write
 *   SlotConfig = 0x000F  →  bajt niski = 0x0F, bajt wysoki = 0x00
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
 * Docelowe KeyConfig[0..15] – 32 bajty (2B na slot, little-endian w EEPROM).
 * Kolejność w tablicy: [bajt_niski_slotu0, bajt_wysoki_slotu0, ...]
 *
 * Sloty 0–7:  P-256 ECC, Private=1, PubInfo=1, Lockable=1
 *   KeyConfig = 0x0033  →  bajt niski = 0x33, bajt wysoki = 0x00
 *
 * Sloty 8–15: Nie-ECC, KeyType=111b=7
 *   KeyConfig = 0x001C  →  bajt niski = 0x1C, bajt wysoki = 0x00
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

/* =========================================================================
 * POMOCNICZE FUNKCJE WEWNĘTRZNE
 * ========================================================================= */

/* Dekoduj 4-bitowy WriteConfig na czytelny string */
static const char *decode_write_config(uint8_t wc) {
    switch (wc) {
        case 0x0: return "Always     (wolny zapis)";
        case 0x1: return "PubInvalid (zapis gdy klucz pub zinvalidowany)";
        case 0x2: return "Never      (zapis zabroniony przez Write cmd)";
        case 0x3: return "Never      (zapis zabroniony przez Write cmd)";
        case 0x4: return "Never      (bit15=1, zapis zabroniony)";
        case 0x5: return "Never      (bit15=1, zapis zabroniony)";
        case 0x6: return "Encrypt    (zaszyfrowany zapis + MAC)";
        case 0x7: return "Encrypt    (zaszyfrowany zapis + MAC)";
        case 0x8: return "Never      (bit15=1)";
        case 0x9: return "Never      (bit15=1)";
        case 0xA: return "Encrypt    (bit14=1, zaszyfrowany)";
        case 0xB: return "Encrypt    (bit14=1, zaszyfrowany)";
        case 0xC: return "Never      (bit15=1)";
        case 0xD: return "Never      (bit15=1)";
        case 0xE: return "Encrypt    (bit14=1, zaszyfrowany)";
        case 0xF: return "Encrypt    (bit14=1, zaszyfrowany)";
        default:  return "???";
    }
}

/* Dekoduj KeyType na string */
static const char *decode_key_type(uint8_t kt) {
    switch (kt) {
        case 4:  return "P-256 ECC";
        case 6:  return "AES-128";
        case 7:  return "Nie-ECC (dane)";
        default: return "RFU";
    }
}

/* Prosty hex dump wiersza */
static void print_hex_line(const char *label, const uint8_t *data, size_t len) {
    printf("  %-20s:", label);
    for (size_t i = 0; i < len; i++) printf(" %02X", data[i]);
    printf("\n");
}

/* =========================================================================
 * atecc608a_read_config()
 * ========================================================================= */
ATCA_STATUS atecc608a_read_config(uint8_t out[CONFIG_ZONE_SIZE]) {
    ATCA_STATUS status = atcab_read_config_zone(out);
    if (status != ATCA_SUCCESS) {
        printf("[CONFIG] BLAD odczytu config zone: 0x%02X\n", status);
    }
    return status;
}

/* =========================================================================
 * atecc608a_print_config()
 * ========================================================================= */
void atecc608a_print_config(const uint8_t cfg[CONFIG_ZONE_SIZE]) {
    printf("\n");
    printf("============================================================\n");
    printf(" ATECC608A – Inspekcja Config Zone (128 bajtow)\n");
    printf("============================================================\n\n");

    /* --- Identyfikacja urządzenia --- */
    printf("[ Identyfikacja ]\n");
    printf("  Numer seryjny (SN[0:8])  : %02X%02X%02X%02X %02X%02X%02X%02X %02X\n",
           cfg[0], cfg[1], cfg[2], cfg[3],
           cfg[8], cfg[9], cfg[10], cfg[11], cfg[12]);
    printf("  RevNum                    : %02X %02X %02X %02X\n",
           cfg[4], cfg[5], cfg[6], cfg[7]);

    /* --- Konfiguracja I2C --- */
    printf("\n[ Interfejs ]\n");
    uint8_t i2c_en   = cfg[CONFIG_OFFSET_I2C_EN];
    uint8_t i2c_addr = cfg[CONFIG_OFFSET_I2C_ADDR];
    printf("  I2C_Enable  [14]          : 0x%02X  (%s)\n",
           i2c_en, (i2c_en & 0x01) ? "I2C" : "Single-Wire");
    printf("  I2C_Address [16]          : 0x%02X  (7-bit: 0x%02X)\n",
           i2c_addr, (i2c_addr >> 1) & 0x7F);

    /* --- OTPmode i ChipMode --- */
    printf("\n[ Tryb urzadzenia ]\n");
    uint8_t otp_mode  = cfg[CONFIG_OFFSET_OTP_MODE];
    uint8_t chip_mode = cfg[CONFIG_OFFSET_CHIP_MODE];
    const char *otp_str = (otp_mode == OTP_MODE_READ_ONLY)   ? "Read-Only (0xAA)" :
                          (otp_mode == OTP_MODE_CONSUMPTION)  ? "Consumption (0x55)" :
                          "Nieznany";
    printf("  OTPmode     [18]          : 0x%02X  (%s)\n", otp_mode, otp_str);
    printf("  ChipMode    [19]          : 0x%02X\n", chip_mode);
    printf("    Bit2 Watchdog           : %s\n",
           (chip_mode & 0x04) ? "10.0s" : "1.3s (zalecane)");
    printf("    Bit1 TTLenable          : %s\n",
           (chip_mode & 0x02) ? "VCC-referenced" : "Fixed reference");
    printf("    Bit0 SelectorMode       : %s\n",
           (chip_mode & 0x01) ? "One-time write" : "Always writeable");

    /* --- Status blokad --- */
    printf("\n[ Status blokad ]\n");
    uint8_t lock_val = cfg[CONFIG_OFFSET_LOCK_VAL];
    uint8_t lock_cfg = cfg[CONFIG_OFFSET_LOCK_CFG];
    bool cfg_locked  = (lock_cfg != ZONE_UNLOCKED);
    bool data_locked = (lock_val != ZONE_UNLOCKED);
    printf("  LockConfig  [87]          : 0x%02X  -> Config zone: %s\n",
           lock_cfg, cfg_locked ? "ZABLOKOWANA" : "odblokowana");
    printf("  LockValue   [86]          : 0x%02X  -> Data/OTP zone: %s\n",
           lock_val, data_locked ? "ZABLOKOWANA" : "odblokowana");

    /* SlotLocked bits */
    uint16_t slot_locked = (uint16_t)cfg[CONFIG_OFFSET_SLOT_LOCK] |
                           ((uint16_t)cfg[CONFIG_OFFSET_SLOT_LOCK + 1] << 8);
    printf("  SlotLocked  [88-89]       : 0x%04X\n", slot_locked);
    printf("    (bit=0 oznacza slot ZABLOKOWANY)\n");
    printf("    Sloty: ");
    for (int s = 0; s < 16; s++) {
        bool locked_slot = !((slot_locked >> s) & 0x01);
        if (locked_slot) printf("%d* ", s);
        else             printf("%d  ", s);
    }
    printf("\n    (* = zablokowany indywidualnie)\n");

    /* --- SlotConfig [20-51] --- */
    printf("\n[ SlotConfig (bajty 20-51) ]\n");
    printf("  %-6s %-10s %-12s %-8s %-8s %-8s %-8s %-8s %-8s %-8s\n",
           "Slot", "Wartość", "WriteConfig", "WriteKey",
           "IsSecret", "EncRead", "LimUse", "NoMac", "ECDH", "ExtSign");
    printf("  %s\n", "--------------------------------------------------------------"
                     "---------------------------------");

    for (int s = 0; s < 16; s++) {
        /* ENDIANNESS: cfg[offset + s*2]     = bajt NISKI  (bits 7:0)
         *             cfg[offset + s*2 + 1] = bajt WYSOKI (bits 15:8)
         * Składamy uint16_t przez lo | (hi << 8) – poprawne dla little-endian EEPROM. */
        uint8_t lo = cfg[CONFIG_OFFSET_SLOT_CFG + s * 2];
        uint8_t hi = cfg[CONFIG_OFFSET_SLOT_CFG + s * 2 + 1];
        uint16_t sc = (uint16_t)lo | ((uint16_t)hi << 8);

        uint8_t write_cfg = (sc >> 12) & 0x0F;
        uint8_t write_key = (sc >> 8)  & 0x0F;
        uint8_t is_secret = (sc >> 7)  & 0x01;
        uint8_t enc_read  = (sc >> 6)  & 0x01;
        uint8_t lim_use   = (sc >> 5)  & 0x01;
        uint8_t no_mac    = (sc >> 4)  & 0x01;
        /* Dla private key slots ReadKey[3:0] jest flaga ECDH/Sign */
        uint8_t rk = sc & 0x0F;
        /* Bit 2 = ECDH permitted (private key context) */
        uint8_t ecdh_ok   = (rk >> 2) & 0x01;
        /* Bit 3 = ECDH output to slot (0=in clear) */
        uint8_t ecdh_enc  = (rk >> 3) & 0x01;
        /* Bit 0 = External signature */
        uint8_t ext_sign  = rk & 0x01;

        printf("  %-5d  0x%04X   %-3X            %-8d %-8d %-8d %-8d %-8d ",
               s, sc, write_cfg, write_key, is_secret, enc_read, lim_use, no_mac);
        if (s <= 7) {
            /* Dla slotów ECC interpretujemy ReadKey jako flagi */
            printf("%s%-3s  %s\n",
                   ecdh_ok  ? "TAK " : "NIE ",
                   ecdh_enc ? "(->slot)" : "(clear)",
                   ext_sign ? "TAK" : "NIE");
        } else {
            /* Dla slotów danych ReadKey to numer klucza */
            printf("N/D          N/D\n");
        }
    }

    /* --- KeyConfig [96-127] --- */
    printf("\n[ KeyConfig (bajty 96-127) ]\n");
    printf("  %-6s %-10s %-16s %-10s %-10s %-10s %-10s %-10s\n",
           "Slot", "Wartość", "KeyType", "Private",
           "PubInfo", "Lockable", "ReqRand", "ReqAuth");
    printf("  %s\n", "--------------------------------------------------------------"
                     "------------------");

    for (int s = 0; s < 16; s++) {
        /* ENDIANNESS: identycznie jak SlotConfig – lo | (hi << 8). */
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
               priv     ? "TAK" : "NIE",
               pub_info ? "TAK" : "NIE",
               lockable ? "TAK" : "NIE",
               req_rand ? "TAK" : "NIE",
               req_auth ? "TAK" : "NIE");
    }

    /* --- Hex dump dla debugowania --- */
    printf("\n[ Pelny hex dump (128 bajtow) ]\n");
    for (int i = 0; i < 128; i++) {
        if (i % 16 == 0) printf("  [%02X] ", i);
        printf("%02X ", cfg[i]);
        if (i % 16 == 15) printf("\n");
    }
    printf("\n============================================================\n\n");
}

/* =========================================================================
 * atecc608a_print_lock_status()
 * ========================================================================= */
void atecc608a_print_lock_status(const uint8_t cfg[CONFIG_ZONE_SIZE]) {
    uint8_t lock_val = cfg[CONFIG_OFFSET_LOCK_VAL];
    uint8_t lock_cfg = cfg[CONFIG_OFFSET_LOCK_CFG];
    uint16_t slot_locked = (uint16_t)cfg[CONFIG_OFFSET_SLOT_LOCK] |
                           ((uint16_t)cfg[CONFIG_OFFSET_SLOT_LOCK + 1] << 8);

    printf("\n[ Status blokad ]\n");
    printf("  Config zone : %s (LockConfig=0x%02X)\n",
           (lock_cfg != ZONE_UNLOCKED) ? "ZABLOKOWANA" : "odblokowana", lock_cfg);
    printf("  Data/OTP    : %s (LockValue=0x%02X)\n",
           (lock_val != ZONE_UNLOCKED) ? "ZABLOKOWANA" : "odblokowana", lock_val);

    for (int s = 0; s < 16; s++) {
        bool slot_lk = !((slot_locked >> s) & 0x01);
        if (slot_lk) {
            printf("  Slot %2d     : ZABLOKOWANY indywidualnie\n", s);
        }
    }
}

/* =========================================================================
 * atecc608a_write_config()
 * ========================================================================= */
ATCA_STATUS atecc608a_write_config(void) {
    ATCA_STATUS status;
    uint8_t cfg[CONFIG_ZONE_SIZE];

    printf("\n[CONFIG] Zapis docelowej konfiguracji...\n");

    /* Krok 1: Odczytaj aktualną konfigurację */
    status = atcab_read_config_zone(cfg);
    if (status != ATCA_SUCCESS) {
        printf("[CONFIG] BLAD: nie mozna odczytac config zone: 0x%02X\n", status);
        return status;
    }

    /* Krok 2: Sprawdź czy config zone jest odblokowana */
    if (cfg[CONFIG_OFFSET_LOCK_CFG] != ZONE_UNLOCKED) {
        printf("[CONFIG] BLAD: config zone jest juz ZABLOKOWANA (LockConfig=0x%02X).\n",
               cfg[CONFIG_OFFSET_LOCK_CFG]);
        printf("         Nie mozna modyfikowac zablokowanej config zone.\n");
        return ATCA_NOT_LOCKED;
    }

    printf("[CONFIG] Config zone odblokowana – mozna zapisywac.\n");

    /* Krok 3: Zapisz SlotConfig[0..15] – bajty 20–51 (32 bajty)
     *
     * atcab_write_bytes_zone() zapisuje bajty do dowolnej strefy.
     * Parametry: zone, slot (0 dla config), offset (bajt startowy), data, len.
     * Dla ATCA_ZONE_CONFIG: slot=0, offset=adres bajtu w config zone.
     *
     * UWAGA: zapis następuje blokami po 4 bajty wyrównanymi do granicy słowa.
     * atcab_write_bytes_zone() obsługuje to automatycznie.
     */
    printf("[CONFIG] Zapisywanie SlotConfig[0..15] (bajty 20-51)...\n");
    status = atcab_write_bytes_zone(ATCA_ZONE_CONFIG, 0,
                                    CONFIG_OFFSET_SLOT_CFG,
                                    TARGET_SLOT_CONFIG,
                                    sizeof(TARGET_SLOT_CONFIG));
    if (status != ATCA_SUCCESS) {
        printf("[CONFIG] BLAD zapisu SlotConfig: 0x%02X\n", status);
        return status;
    }
    printf("[CONFIG] SlotConfig: OK\n");

    /* Krok 4: Zapisz KeyConfig[0..15] – bajty 96–127 (32 bajty) */
    printf("[CONFIG] Zapisywanie KeyConfig[0..15] (bajty 96-127)...\n");
    status = atcab_write_bytes_zone(ATCA_ZONE_CONFIG, 0,
                                    CONFIG_OFFSET_KEY_CFG,
                                    TARGET_KEY_CONFIG,
                                    sizeof(TARGET_KEY_CONFIG));
    if (status != ATCA_SUCCESS) {
        printf("[CONFIG] BLAD zapisu KeyConfig: 0x%02X\n", status);
        return status;
    }
    printf("[CONFIG] KeyConfig: OK\n");

    /* Krok 5: Ustaw OTPmode = Read-Only (bajt 18)
     *
     * UWAGA: bajt 18 jest częścią słowa [16..19].
     * Musimy zapisać całe słowo (4 bajty wyrównane do granicy 4B).
     * Bajty 16 i 17 są tylko do odczytu przez Microchip – czytamy aktualne
     * wartości i nadpisujemy tylko bajt 18.
     */
    printf("[CONFIG] Ustawianie OTPmode = Read-Only (bajt 18)...\n");
    uint8_t word16_19[4];
    status = atcab_read_bytes_zone(ATCA_ZONE_CONFIG, 0, 16, word16_19, 4);
    if (status != ATCA_SUCCESS) {
        printf("[CONFIG] BLAD odczytu bajtow 16-19: 0x%02X\n", status);
        return status;
    }
    word16_19[2] = OTP_MODE_READ_ONLY; /* bajt 18 = OTPmode */
    /* bajt 19 = ChipMode: zostawiamy bez zmian (domyślnie 0x00 = poprawne) */
    status = atcab_write_bytes_zone(ATCA_ZONE_CONFIG, 0, 16, word16_19, 4);
    if (status != ATCA_SUCCESS) {
        printf("[CONFIG] BLAD zapisu OTPmode: 0x%02X\n", status);
        return status;
    }
    printf("[CONFIG] OTPmode: OK\n");

    printf("[CONFIG] Zapis konfiguracji: ZAKOŃCZONY POMYŚLNIE.\n");
    printf("[CONFIG] Uruchom atecc608a_verify_config() przed lockowaniem!\n");
    return ATCA_SUCCESS;
}

/* =========================================================================
 * atecc608a_verify_config()
 * ========================================================================= */
ATCA_STATUS atecc608a_verify_config(void) {
    ATCA_STATUS status;
    uint8_t cfg[CONFIG_ZONE_SIZE];
    bool ok = true;

    printf("\n[VERIFY] Weryfikacja konfiguracji chipa...\n");

    status = atcab_read_config_zone(cfg);
    if (status != ATCA_SUCCESS) {
        printf("[VERIFY] BLAD odczytu: 0x%02X\n", status);
        return status;
    }

    /* Sprawdź SlotConfig[0..15] */
    for (int s = 0; s < 16; s++) {
        /* ENDIANNESS: odczyt z EEPROM = little-endian: cfg[offset] = LO, cfg[offset+1] = HI.
         * Porównujemy bajt po bajcie z tablicą TARGET która ma identyczny układ.
         * Do wyświetlania składamy uint16_t przez lo|(hi<<8) aby pokazać wartość logiczną. */
        uint8_t actual_lo = cfg[CONFIG_OFFSET_SLOT_CFG + s * 2];
        uint8_t actual_hi = cfg[CONFIG_OFFSET_SLOT_CFG + s * 2 + 1];
        uint8_t target_lo = TARGET_SLOT_CONFIG[s * 2];
        uint8_t target_hi = TARGET_SLOT_CONFIG[s * 2 + 1];

        if (actual_lo != target_lo || actual_hi != target_hi) {
            /* Wyświetlamy jako uint16_t (wartość logiczna), nie jako surowe bajty HI:LO */
            uint16_t actual = (uint16_t)actual_lo | ((uint16_t)actual_hi << 8);
            uint16_t target = (uint16_t)target_lo | ((uint16_t)target_hi << 8);
            printf("[VERIFY]   NIEZGODNOSC SlotConfig[%d]: mam 0x%04X, oczekuje 0x%04X\n",
                   s, actual, target);
            printf("[VERIFY]     (surowe bajty: mam [LO=0x%02X HI=0x%02X],"
                   " oczekuje [LO=0x%02X HI=0x%02X])\n",
                   actual_lo, actual_hi, target_lo, target_hi);
            ok = false;
        }
    }
    if (ok) printf("[VERIFY]   SlotConfig: OK\n");

    /* Sprawdź KeyConfig[0..15] */
    bool kc_ok = true;
    printf("[VERIFY] KeyConfig[0..15]...\n");
    for (int s = 0; s < 16; s++) {
        /* ENDIANNESS: identycznie jak SlotConfig. */
        uint8_t actual_lo = cfg[CONFIG_OFFSET_KEY_CFG + s * 2];
        uint8_t actual_hi = cfg[CONFIG_OFFSET_KEY_CFG + s * 2 + 1];
        uint8_t target_lo = TARGET_KEY_CONFIG[s * 2];
        uint8_t target_hi = TARGET_KEY_CONFIG[s * 2 + 1];

        if (actual_lo != target_lo || actual_hi != target_hi) {
            uint16_t actual = (uint16_t)actual_lo | ((uint16_t)actual_hi << 8);
            uint16_t target = (uint16_t)target_lo | ((uint16_t)target_hi << 8);
            printf("[VERIFY]   NIEZGODNOSC KeyConfig[%d]: mam 0x%04X, oczekuje 0x%04X\n",
                   s, actual, target);
            printf("[VERIFY]     (surowe bajty: mam [LO=0x%02X HI=0x%02X],"
                   " oczekuje [LO=0x%02X HI=0x%02X])\n",
                   actual_lo, actual_hi, target_lo, target_hi);
            kc_ok = false;
            ok = false;
        }
    }
    if (kc_ok) printf("[VERIFY]   KeyConfig: OK\n");

    /* Sprawdź OTPmode */
    uint8_t otp_mode = cfg[CONFIG_OFFSET_OTP_MODE];
    if (otp_mode != OTP_MODE_READ_ONLY) {
        printf("[VERIFY]   OTPmode NIEZGODNY: mam 0x%02X, oczekuję 0x%02X (Read-Only)\n",
               otp_mode, OTP_MODE_READ_ONLY);
        ok = false;
    } else {
        printf("[VERIFY]   OTPmode: OK (0xAA = Read-Only)\n");
    }

    /* Podsumowanie */
    if (ok) {
        printf("[VERIFY] WYNIK: OK – konfiguracja zgodna z docelową.\n");
        printf("[VERIFY] Mozna wywolac atecc608a_lock_config_zone(true).\n");
        return ATCA_SUCCESS;
    } else {
        printf("[VERIFY] WYNIK: BLAD – niezgodność konfiguracji. NIE lockuj!\n");
        return ATCA_GEN_FAIL;
    }
}

/* =========================================================================
 * atecc608a_lock_config_zone()
 * ========================================================================= */
ATCA_STATUS atecc608a_lock_config_zone(bool confirm) {
    if (!confirm) {
        printf("[LOCK] Wywolaj z confirm=true aby potwierdzic. NIEODWRACALNE!\n");
        return ATCA_GEN_FAIL;
    }

    printf("\n[LOCK] !!! BLOKOWANIE CONFIG ZONE – NIEODWRACALNE !!!\n");

    /* Ostateczna weryfikacja przed lockowaniem */
    ATCA_STATUS verify_status = atecc608a_verify_config();
    if (verify_status != ATCA_SUCCESS) {
        printf("[LOCK] PRZERWANO: weryfikacja konfiguracji nie powiodla sie.\n");
        printf("[LOCK] Najpierw napraw konfiguracje przez atecc608a_write_config().\n");
        return ATCA_GEN_FAIL;
    }

    /* Wykonaj lock.
     * atcab_lock_config_zone() wylicza CRC config zone i wywołuje Lock command.
     * Jeśli CRC się nie zgadza → zwraca błąd (chip nie lockuje).
     * To jest dodatkowe zabezpieczenie przed przypadkowym lockowaniem.
     */
    ATCA_STATUS status = atcab_lock_config_zone();
    if (status != ATCA_SUCCESS) {
        printf("[LOCK] BLAD lockowania config zone: 0x%02X\n", status);
        printf("[LOCK] Mozliwe przyczyny: CRC mismatch, chip juz zablokowany.\n");
        return status;
    }

    printf("[LOCK] Config zone ZABLOKOWANA pomyslnie.\n");
    printf("[LOCK] Nastepny krok: wygeneruj klucze (atcab_genkey) a potem\n");
    printf("[LOCK] wywolaj atecc608a_lock_data_zone(true).\n");
    return ATCA_SUCCESS;
}

/* =========================================================================
 * atecc608a_lock_data_zone()
 * ========================================================================= */
ATCA_STATUS atecc608a_lock_data_zone(bool confirm) {
    if (!confirm) {
        printf("[LOCK] Wywolaj z confirm=true aby potwierdzic. NIEODWRACALNE!\n");
        return ATCA_GEN_FAIL;
    }

    /* Sprawdź czy config zone jest zablokowana (wymagane przed data lock) */
    uint8_t cfg[CONFIG_ZONE_SIZE];
    ATCA_STATUS status = atcab_read_config_zone(cfg);
    if (status != ATCA_SUCCESS) {
        printf("[LOCK] BLAD odczytu config zone: 0x%02X\n", status);
        return status;
    }

    if (cfg[CONFIG_OFFSET_LOCK_CFG] == ZONE_UNLOCKED) {
        printf("[LOCK] BLAD: Config zone musi byc zablokowana przed lockowaniem danych.\n");
        return ATCA_GEN_FAIL;
    }

    if (cfg[CONFIG_OFFSET_LOCK_VAL] != ZONE_UNLOCKED) {
        printf("[LOCK] BLAD: Data/OTP zone jest juz zablokowana.\n");
        return ATCA_NOT_LOCKED;
    }

    printf("\n[LOCK] !!! BLOKOWANIE DATA/OTP ZONE – NIEODWRACALNE !!!\n");
    printf("[LOCK] Po tym kroku sloty ECC beda gotowe do uzycia.\n");

    /* atcab_lock_data_zone() z CRC summary.
     * UWAGA: dla slotów ECC (Private=1) ich zawartość NIE jest włączana
     * do CRC summary (zgodnie z datasheet §9.10).
     * CRC jest liczone tylko ze slotów danych (nie-private).
     */
    status = atcab_lock_data_zone();
    if (status != ATCA_SUCCESS) {
        printf("[LOCK] BLAD lockowania data zone: 0x%02X\n", status);
        return status;
    }

    printf("[LOCK] Data/OTP zone ZABLOKOWANA pomyslnie.\n");
    printf("[LOCK] Urzadzenie gotowe. Mozesz generowac klucze przez atcab_genkey().\n");
    return ATCA_SUCCESS;
}

/* =========================================================================
 * atecc608a_check_key_slot()
 * ========================================================================= */
ATCA_STATUS atecc608a_check_key_slot(uint8_t slot, uint8_t out_pubkey[64]) {
    if (slot > PICO_CRYPT_ECC_SLOT_MAX) {
        printf("[KEY] Slot %d poza zakresem ECC (0-%d).\n",
               slot, PICO_CRYPT_ECC_SLOT_MAX);
        return ATCA_BAD_PARAM;
    }

    uint8_t pubkey_buf[64];
    /* atcab_get_pubkey() wysyła GenKey(Mode=0) – TYLKO oblicza klucz publiczny
     * z istniejącego klucza prywatnego, BEZ generowania nowego klucza.
     * Jeśli slot jest pusty → zwraca błąd (ATCA_EXECUTION_ERROR lub ATCA_GEN_FAIL). */
    ATCA_STATUS status = atcab_get_pubkey(slot, pubkey_buf);

    if (status == ATCA_SUCCESS) {
        if (out_pubkey != NULL) {
            memcpy(out_pubkey, pubkey_buf, 64);
        }
        return ATCA_SUCCESS;
    } else {
        /* Slot pusty lub błąd */
        return status;
    }
}

/* =========================================================================
 * atecc608a_print_all_keys()
 * ========================================================================= */
void atecc608a_print_all_keys(void) {
    printf("\n[ Stan kluczy ECC (sloty 0-%d) ]\n", PICO_CRYPT_ECC_SLOT_MAX);
    printf("  %-6s %-12s %-16s\n", "Slot", "Status", "Fingerprint (SHA256[:8])");
    printf("  %s\n", "--------------------------------------------");

    for (uint8_t s = 0; s <= PICO_CRYPT_ECC_SLOT_MAX; s++) {
        uint8_t pubkey[64];
        ATCA_STATUS status = atecc608a_check_key_slot(s, pubkey);

        if (status == ATCA_SUCCESS) {
            /* Prosty fingerprint: SHA256(pubkey)[0:7] przez chip */
            uint8_t digest[32];
            ATCA_STATUS sha_st = atcab_sha(64, pubkey, digest);
            if (sha_st == ATCA_SUCCESS) {
                printf("  %-5d  %-12s %02X%02X%02X%02X%02X%02X%02X%02X%s\n",
                       s, "ISTNIEJE",
                       digest[0], digest[1], digest[2], digest[3],
                       digest[4], digest[5], digest[6], digest[7],
                       (s == 0) ? "  (domyslny)" : "");
            } else {
                printf("  %-5d  %-12s (SHA blad: 0x%02X)\n", s, "ISTNIEJE", sha_st);
            }
        } else {
            printf("  %-5d  %-12s\n", s, "pusty");
        }
    }
    printf("\n");
}
