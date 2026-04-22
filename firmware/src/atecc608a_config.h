/**
 * atecc608a_config.h
 *
 * Definicja strefy konfiguracyjnej ATECC608A dla projektu pico-crypt.
 *
 * UKŁAD SLOTÓW (sloty 0–7 to klucze ECC dla użytkownika):
 *
 *  Slot  Rozmiar  Przeznaczenie                    ECDH  GenKey  Sygn.
 *  ----  -------  ------------------------------   ----  ------  -----
 *    0    36B      ECC P-256 klucz #0 (domyślny)    TAK   TAK     TAK
 *    1    36B      ECC P-256 klucz #1                TAK   TAK     TAK
 *    2    36B      ECC P-256 klucz #2                TAK   TAK     TAK
 *    3    36B      ECC P-256 klucz #3                TAK   TAK     TAK
 *    4    36B      ECC P-256 klucz #4                TAK   TAK     TAK
 *    5    36B      ECC P-256 klucz #5                TAK   TAK     TAK
 *    6    36B      ECC P-256 klucz #6                TAK   TAK     TAK
 *    7    36B      ECC P-256 klucz #7                TAK   TAK     TAK
 *    8   416B      Dane ogólne (publiczne certyfikaty / klucze pub)
 *    9    72B      Dane ogólne (rezerwa)
 *   10    72B      Dane ogólne (rezerwa)
 *   11    72B      Dane ogólne (rezerwa)
 *   12    72B      Dane ogólne (rezerwa)
 *   13    72B      Dane ogólne (rezerwa)
 *   14    72B      Dane ogólne (rezerwa)
 *   15    72B      Dane ogólne (rezerwa)
 *
 * KONFIGURACJA SLOTÓW 0–7 (ECC private key, ECDH output in clear):
 *
 *   SlotConfig (2 bajty, little-endian w config zone):
 *     Bit  0   (ReadKey[0]) = 1  → External signatures (Sign z zewn. wiad.) WŁĄCZONE
 *     Bit  1   (ReadKey[1]) = 1  → Internal signatures (Sign z GenDig/GenKey) WŁĄCZONE
 *     Bit  2   (ReadKey[2]) = 1  → ECDH PERMITTED ← kluczowy
 *     Bit  3   (ReadKey[3]) = 0  → ECDH output IN CLEAR (nie do slotu N+1) ← kluczowy
 *     Bit  4   (NoMac)      = 0  → Klucz może być używany z MAC/HMAC
 *     Bit  5   (LimitedUse) = 0  → Bez limitu użyć
 *     Bit  6   (EncryptRead)= 0  → Nie dotyczy (private key – nie można czytać)
 *     Bit  7   (IsSecret)   = 1  → Zawartość TAJNA (wymagane dla ECC private key)
 *     Bits 11-8 (WriteKey)  = 0  → WriteKey = slot 0 (referencyjny, nie używany)
 *     Bits 15-12 (WriteConfig)= 0010b = 0x2  → Never (Write command zabroniony)
 *                                               GenKey MOŻE zapisywać (bit 13 = 1)
 *
 *   Wartość SlotConfig: 0b 0010 0000 1000 0111 = 0x2087
 *   Bajt niski (config[20 + slot*2])   = 0x87
 *   Bajt wysoki (config[20 + slot*2+1]) = 0x20
 *
 *   KeyConfig (2 bajty):
 *     Bit  0   (Private)    = 1  → Zawiera ECC private key
 *     Bit  1   (PubInfo)    = 1  → Klucz publiczny zawsze dostępny przez GenKey(Public)
 *     Bits 4-2 (KeyType)    = 100b = 4 → P-256 NIST ECC key
 *     Bit  5   (Lockable)   = 1  → Slot może być indywidualnie zablokowany
 *     Bit  6   (ReqRandom)  = 0  → Losowy nonce nie jest wymagany
 *     Bit  7   (ReqAuth)    = 0  → Brak wymogu autoryzacji przed użyciem
 *     Bits 11-8 (AuthKey)   = 0  → Nie używane (ReqAuth=0)
 *     Bit  12  (IntrusionDisable) = 0 → Niezależny od IntrusionLatch
 *     Bit  13  (RFU)        = 0  → Zarezerwowane
 *     Bits 15-14 (X509id)   = 00 → Bez X.509 format restriction
 *
 *   Wartość KeyConfig: 0b 0000 0000 0010 0111 = 0x0033
 *   Bajt niski (config[96 + slot*2])   = 0x33
 *   Bajt wysoki (config[96 + slot*2+1]) = 0x00
 *
 * KONFIGURACJA SLOTÓW 8–15 (dane publiczne, brak kluczy prywatnych):
 *
*   SlotConfig: 0x000F
 *     Bits 3-0 (ReadKey)       = 0xF  → ReadKey=15 (unika CheckMac/Copy, per datasheet ostrzeżenie)
 *     Bit  4   (NoMac)         = 0    → Dozwolone z MAC/HMAC
 *     Bit  5   (LimitedUse)    = 0    → BEZ limitu użyć (nie powiązany z Counter<0>)
 *     Bit  6   (EncryptRead)   = 0    → Cleartext reads dozwolone
 *     Bit  7   (IsSecret)      = 0    → Dane PUBLICZNE – cleartext reads dozwolone
 *                                        (IsSecret=0, EncryptRead=0 → Table 2-7: reads always permitted)
 *     Bits 11-8 (WriteKey)     = 0    → Nie używane przy WriteConfig=Always
 *     Bits 15-12 (WriteConfig) = 0000b → Always (zawsze można zapisać)
 *
 *   Wartość SlotConfig: 0b 0000 0000 0000 1111 = 0x000F
 *   Bajt niski  = 0x0F, Bajt wysoki = 0x00
 *
 *   KeyConfig: 0x001C
 *     Bit  0   (Private)    = 0  → Nie ECC private key
 *     Bit  1   (PubInfo)    = 0  → Nie dotyczy
 *     Bits 4-2 (KeyType)    = 111b = 7 → Nie ECC key
 *     Bit  5   (Lockable)   = 0  → Slot nie może być indywidualnie blokowany
 *
 *   Wartość KeyConfig: 0b 0000 0000 0001 1100 = 0x001C
 *   Bajt niski  = 0x1C, Bajt wysoki = 0x00
 */

#pragma once
#include <stdint.h>
#include <stdbool.h>
#include "cryptoauthlib.h"

/* =========================================================================
 * STAŁE KONFIGURACYJNE
 * ========================================================================= */

#define PICO_CRYPT_ECC_SLOT_MIN    0
#define PICO_CRYPT_ECC_SLOT_MAX    7
#define PICO_CRYPT_ECC_SLOT_COUNT  8    /* sloty 0–7: klucze ECC dla użytkownika */
#define PICO_CRYPT_DATA_SLOT_MIN   8
#define PICO_CRYPT_DATA_SLOT_MAX   15

/*
 * SlotConfig dla slotów ECC (0–7): 0x2087
 *
 * Dekodowanie bitów (datasheet Table 2-6):
 *   Dla private key slot ReadKey[3:0] ma inne znaczenie niż dla danych:
 *   Bit 0: External signature = 1
 *   Bit 1: Internal signature = 1
 *   Bit 2: ECDH permitted     = 1
 *   Bit 3: ECDH output in clear = 0
 *   Bit 4: NoMac   = 0
 *   Bit 5: LimitedUse = 0
 *   Bit 6: EncryptRead = 0 (nie dotyczy private key)
 *   Bit 7: IsSecret = 1  (wymagane dla private key!)
 *   Bits 11-8: WriteKey = 0
 *   Bits 15-12: WriteConfig = 0010 → bit 13=1: GenKey może zapisywać
 *                                     bit 12=0: Write command = Never
 */
#define SLOT_CONFIG_ECC_LO   0x87u   /* bajt niski  SlotConfig[7:0]  */
#define SLOT_CONFIG_ECC_HI   0x20u   /* bajt wysoki SlotConfig[15:8] */
#define SLOT_CONFIG_ECC_WORD 0x2087u

/*
 * KeyConfig dla slotów ECC (0–7): 0x0033
 *
 * Dekodowanie (datasheet Table 2-12):
 *   Bit  0: Private   = 1  (ECC private key)
 *   Bit  1: PubInfo   = 1  (GenKey(Public) zawsze dozwolone)
 *   Bits 4-2: KeyType = 100b = 4  (P-256)
 *   Bit  5: Lockable  = 1  (indywidualny lock przez Lock command)
 *   Bit  6: ReqRandom = 0
 *   Bit  7: ReqAuth   = 0
 *   Bits 15-8: = 0
 */
#define KEY_CONFIG_ECC_LO    0x33u   /* bajt niski  KeyConfig[7:0]  */
#define KEY_CONFIG_ECC_HI    0x00u   /* bajt wysoki KeyConfig[15:8] */
#define KEY_CONFIG_ECC_WORD  0x0033u

/*
 * SlotConfig dla slotów danych (8–15): 0x000F
 *
 *   Bit  7: IsSecret    = 0 → dane publiczne, cleartext reads DOZWOLONE (Table 2-7)
 *   Bit  5: LimitedUse  = 0 → bez limitu użyć, nie powiązany z Counter<0>
 *   Bit  6: EncryptRead = 0 → brak szyfrowania odczytu
 *   Bits 3-0: ReadKey   = 0xF → unikamy ReadKey=0 (CheckMac/Copy, per datasheet ostrzeżenie)
 *   Bits 11-8: WriteKey = 0 → nie używane przy WriteConfig=Always
 *   Bits 15-12: WriteConfig = 0000 = Always → wolne zapisy zawsze dozwolone
 */
#define SLOT_CONFIG_DATA_LO  0x0Fu
#define SLOT_CONFIG_DATA_HI  0x00u
#define SLOT_CONFIG_DATA_WORD 0x000Fu

/*
 * KeyConfig dla slotów danych (8–15): 0x001C
 *
 *   Bit  0: Private   = 0
 *   Bit  1: PubInfo   = 0
 *   Bits 4-2: KeyType = 111b = 7 (Not an ECC key – wymagane dla non-ECC)
 *   Bit  5: Lockable  = 0
 */
#define KEY_CONFIG_DATA_LO   0x1Cu
#define KEY_CONFIG_DATA_HI   0x00u
#define KEY_CONFIG_DATA_WORD 0x001Cu

/* Pozycje bajtów w config zone (128 bajtów total) */
#define CONFIG_ZONE_SIZE        128
#define CONFIG_OFFSET_SN0       0    /* SN[0:3] – 4 bajty (RO) */
#define CONFIG_OFFSET_REVNUM    4    /* RevNum – 4 bajty (RO) */
#define CONFIG_OFFSET_SN4       8    /* SN[4:8] – 5 bajtów (RO) */
#define CONFIG_OFFSET_I2C_EN    14   /* I2C_Enable */
#define CONFIG_OFFSET_I2C_ADDR  16   /* I2C_Address */
#define CONFIG_OFFSET_OTP_MODE  18   /* OTPmode */
#define CONFIG_OFFSET_CHIP_MODE 19   /* ChipMode */
#define CONFIG_OFFSET_SLOT_CFG  20   /* SlotConfig[0..15] – 32 bajty (2B na slot) */
#define CONFIG_OFFSET_COUNTER0  52   /* Counter<0> – 8 bajtów */
#define CONFIG_OFFSET_COUNTER1  60   /* Counter<1> – 8 bajtów */
#define CONFIG_OFFSET_LAST_KEY  68   /* LastKeyUse – 16 bajtów */
#define CONFIG_OFFSET_USER_XTRA 84   /* UserExtra */
#define CONFIG_OFFSET_SELECTOR  85   /* Selector */
#define CONFIG_OFFSET_LOCK_VAL  86   /* LockValue */
#define CONFIG_OFFSET_LOCK_CFG  87   /* LockConfig */
#define CONFIG_OFFSET_SLOT_LOCK 88   /* SlotLocked – 2 bajty */
#define CONFIG_OFFSET_X509      92   /* X509format – 4 bajty */
#define CONFIG_OFFSET_KEY_CFG   96   /* KeyConfig[0..15] – 32 bajty (2B na slot) */

/* Wartości LockConfig / LockValue */
#define ZONE_UNLOCKED  0x55u
#define ZONE_LOCKED    0x00u

/* OTPmode */
#define OTP_MODE_READ_ONLY   0xAAu
#define OTP_MODE_CONSUMPTION 0x55u

/* =========================================================================
 * DOCELOWA CONFIG ZONE (128 BAJTÓW)
 *
 * Bajty 0–15: zarządzane przez Microchip (SN, RevNum, I2C) – nie nadpisujemy.
 * Bajty 16–19: I2C_Address, Reserved, OTPmode, ChipMode – ustawiamy.
 * Bajty 20–51: SlotConfig[0..15] – definiujemy poniżej.
 * Bajty 52–95: Counter, LastKeyUse, UserExtra, Selector, LockValue, LockConfig,
 *              SlotLocked, RFU, X509format – używamy wartości domyślnych lub 0.
 * Bajty 96–127: KeyConfig[0..15] – definiujemy poniżej.
 *
 * UWAGA: Nie zapisujemy całej config zone naraz – używamy atcab_write_bytes_zone()
 * dla konkretnych bajtów. Bajty 0–15 i bajty zarządzane przez Microchip
 * (RevNum, SN) są tylko do odczytu.
 * ========================================================================= */

/* Pełna config zone do weryfikacji (128B).
 * Bajty 0–15 są wypełniane z atcab_read_config_zone() – tu placeholder 0x00.
 * Bajty zapisywalne zdefiniowane poniżej. */
typedef struct {
    uint8_t bytes[CONFIG_ZONE_SIZE];
} config_zone_t;

/* =========================================================================
 * DEKLARACJE FUNKCJI
 * ========================================================================= */

/**
 * atecc608a_read_config()
 * Odczytuje pełną strefę konfiguracyjną (128B) do bufora out.
 * Bezpieczna do wywołania PRZED lockowaniem.
 */
ATCA_STATUS atecc608a_read_config(uint8_t out[CONFIG_ZONE_SIZE]);

/**
 * atecc608a_print_config()
 * Drukuje szczegółową interpretację config zone przez USB CDC (printf).
 * Pokazuje każdy slot z komentarzem: typ klucza, uprawnienia, status.
 */
void atecc608a_print_config(const uint8_t cfg[CONFIG_ZONE_SIZE]);

/**
 * atecc608a_write_config()
 * Zapisuje docelową konfigurację do chipa.
 *
 * WARUNEK: config zone MUSI być odblokowana (LockConfig == 0x55).
 * Funkcja:
 *   1. Sprawdza czy config zone jest odblokowana.
 *   2. Zapisuje SlotConfig[0..15] (bajty 20–51).
 *   3. Zapisuje KeyConfig[0..15] (bajty 96–127).
 *   4. Ustawia OTPmode = Read-Only (bajt 18).
 *   5. Nie rusza bajtów 0–15 (RO), nie lockuje.
 *
 * Zwraca ATCA_SUCCESS jeśli ok, ATCA_NOT_LOCKED jeśli config już zablokowana.
 */
ATCA_STATUS atecc608a_write_config(void);

/**
 * atecc608a_verify_config()
 * Weryfikuje że aktualna konfiguracja chipa ZGADZA SIĘ z docelową.
 * Porównuje bajty 18–19, 20–51, 96–127.
 *
 * Zwraca ATCA_SUCCESS jeśli konfiguracja jest poprawna.
 * Zwraca ATCA_GEN_FAIL jeśli jest niezgodność (wypisuje które bajty).
 */
ATCA_STATUS atecc608a_verify_config(void);

/**
 * atecc608a_lock_config_zone()
 * Blokuje config zone. NIEODWRACALNE.
 *
 * WARUNEK: atecc608a_verify_config() musi zwrócić ATCA_SUCCESS PRZED wywołaniem.
 * Funkcja wymaga potwierdzenia (wywołaj z confirm=true).
 *
 * Po wykonaniu: LockConfig == 0x00, config zone nigdy nie będzie modyfikowana.
 */
ATCA_STATUS atecc608a_lock_config_zone(bool confirm);

/**
 * atecc608a_lock_data_zone()
 * Blokuje Data i OTP zone. NIEODWRACALNE.
 *
 * WARUNEK: config zone musi być ZABLOKOWANA.
 * Funkcja wymaga potwierdzenia (wywołaj z confirm=true).
 */
ATCA_STATUS atecc608a_lock_data_zone(bool confirm);

/**
 * atecc608a_print_lock_status()
 * Drukuje aktualny status blokad:
 *   - LockConfig (czy config zone jest zablokowana)
 *   - LockValue  (czy data/OTP zone są zablokowane)
 *   - SlotLocked[0..15]
 */
void atecc608a_print_lock_status(const uint8_t cfg[CONFIG_ZONE_SIZE]);

/**
 * atecc608a_check_key_slot()
 * Sprawdza czy w podanym slocie (0–7) istnieje klucz ECC.
 * Używa atcab_get_pubkey() – sukces = klucz istnieje.
 *
 * out_pubkey: jeśli != NULL i klucz istnieje, wypełniane 64 bajtami (X||Y).
 * Zwraca ATCA_SUCCESS jeśli klucz istnieje.
 */
ATCA_STATUS atecc608a_check_key_slot(uint8_t slot, uint8_t out_pubkey[64]);

/**
 * atecc608a_print_all_keys()
 * Sprawdza sloty 0–7 i drukuje które mają klucze (fingerprint SHA256[:8]).
 * Wymaga zablokowanej data zone (po Lock).
 */
void atecc608a_print_all_keys(void);
