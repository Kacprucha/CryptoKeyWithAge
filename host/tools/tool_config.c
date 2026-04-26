/**
* Host tool for managing the ATECC608A config zone via Pico USB. *
* Add support for the CMD_CONFIG_OP (0x10) command to the firmware:
* Payload[0] = operation:
* 0x01 = READ_CONFIG → returns a 128B config zone
* 0x02 = WRITE_CONFIG → saves the target configuration
* 0x03 = LOCK_CONFIG → locks the config zone (irreversible)
* 0x04 = LOCK_DATA → locks the data/OTP zone (irreversible)
*
* Usage:
* ./tool_config /dev/ttyACM0 read → read and display config
* ./tool_config /dev/ttyACM0 write → save the target configuration
* ./tool_config /dev/ttyACM0 verify → compare with the target
* ./tool_config /dev/ttyACM0 lock-config → lock the config zone (!!)
* ./tool_config /dev/ttyACM0 lock-data → lock the data zone (!!)
* ./tool_config /dev/ttyACM0 genkey <slot> → generate a key in slots 0-7
* ./tool_config /dev/ttyACM0 keys → show the status of all keys
*
* IMPORTANT ORDER:
* 1. read → check the initial status
* 2. write → save the configuration
* 3. verify → ensure the write was successful
* 4. read → re-inspect
* 5. lock-config → IRREVERSIBLE
* 6. genkey 0 → generate a key in slot 0
* 7. genkey 1 → optional additional keys
* 8. keys → check key status
* 9. lock-data → IRREVERSIBLE (finalization)
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "device.h"
#include "protocol.h"

#define CMD_CONFIG_OP     0x10
#define CMD_GEN_KEY       0x05

#define OP_READ_CONFIG    0x01
#define OP_WRITE_CONFIG   0x02
#define OP_LOCK_CONFIG    0x03
#define OP_LOCK_DATA      0x04

#define CONFIG_ZONE_SIZE  128

#define CONFIG_OFFSET_LOCK_VAL  86
#define CONFIG_OFFSET_LOCK_CFG  87
#define CONFIG_OFFSET_SLOT_LOCK 88
#define CONFIG_OFFSET_SLOT_CFG  20
#define CONFIG_OFFSET_KEY_CFG   96
#define ZONE_UNLOCKED 0x55

static void print_hex(const uint8_t *data, size_t len) 
{
    for (size_t i = 0; i < len; i++) 
    {
        printf("%02X ", data[i]);
    }
    printf("\n");
}

static void print_config_zone(const uint8_t cfg[CONFIG_ZONE_SIZE]) 
{
    printf("\n");
    printf("============================================================\n");
    printf(" ATECC608A – Config Zone (from device)\n");
    printf("============================================================\n\n");

    printf("[ Identification ]\n");
    printf("  SN[0:3]  : %02X %02X %02X %02X\n",
           cfg[0], cfg[1], cfg[2], cfg[3]);
    printf("  RevNum   : %02X %02X %02X %02X\n",
           cfg[4], cfg[5], cfg[6], cfg[7]);
    printf("  SN[4:8]  : %02X %02X %02X %02X %02X\n",
           cfg[8], cfg[9], cfg[10], cfg[11], cfg[12]);

    printf("\n[ Interface ]\n");
    printf("  I2C_Enable  [14]: 0x%02X  (%s)\n",
           cfg[14], (cfg[14] & 0x01) ? "I2C" : "Single-Wire");
    printf("  I2C_Address [16]: 0x%02X  (7-bit: 0x%02X)\n",
           cfg[16], (cfg[16] >> 1) & 0x7F);
    printf("  OTPmode     [18]: 0x%02X  (%s)\n",
           cfg[18],
           cfg[18] == 0xAA ? "Read-Only" :
           cfg[18] == 0x55 ? "Consumption" : "Unknown");
    printf("  ChipMode    [19]: 0x%02X\n", cfg[19]);

    printf("\n[ Lock Status ]\n");
    uint8_t lock_cfg = cfg[CONFIG_OFFSET_LOCK_CFG];
    uint8_t lock_val = cfg[CONFIG_OFFSET_LOCK_VAL];
    uint16_t slot_locked = (uint16_t)cfg[CONFIG_OFFSET_SLOT_LOCK] |
                           ((uint16_t)cfg[CONFIG_OFFSET_SLOT_LOCK + 1] << 8);

    printf("  LockConfig [87]: 0x%02X  -> Config zone: %s\n",
           lock_cfg, lock_cfg != ZONE_UNLOCKED ? "LOCKED" : "UNLOCKED");
    printf("  LockValue  [86]: 0x%02X  -> Data zone:   %s\n",
           lock_val, lock_val != ZONE_UNLOCKED ? "LOCKED" : "UNLOCKED");
    printf("  SlotLocked [88-89]: 0x%04X  (bit=0 → slot locked)\n", slot_locked);

    printf("\n[ SlotConfig (bajty 20-51) ]\n");
    printf("  Slot  Value   IsSecret  ECDH  ExtSign  WriteConfig(bits15-12)\n");
    printf("  ------------------------------------------------------------------\n");
    for (int s = 0; s < 16; s++) 
    {

        uint8_t lo = cfg[CONFIG_OFFSET_SLOT_CFG + s * 2];
        uint8_t hi = cfg[CONFIG_OFFSET_SLOT_CFG + s * 2 + 1];
        uint16_t sc = (uint16_t)lo | ((uint16_t)hi << 8);
        uint8_t is_secret = (sc >> 7) & 0x01;
        uint8_t write_cfg = (sc >> 12) & 0x0F;
        uint8_t ecdh_ok = (sc >> 2) & 0x01;  
        uint8_t ext_sign = sc & 0x01;          

        printf("  %2d    0x%04X   %-9s %-5s %-8s 0x%X\n",
               s, sc,
               is_secret ? "YES" : "NO",
               ecdh_ok   ? "YES" : "NO",
               ext_sign  ? "YES" : "NO",
               write_cfg);
    }

    printf("\n[ KeyConfig (bajts 96-127) ]\n");
    printf("  Slot  Value   Private  KeyType  PubInfo  Lockable\n");
    printf("  ---------------------------------------------------\n");
    for (int s = 0; s < 16; s++) 
    {
        uint8_t lo = cfg[CONFIG_OFFSET_KEY_CFG + s * 2];
        uint8_t hi = cfg[CONFIG_OFFSET_KEY_CFG + s * 2 + 1];
        uint16_t kc = (uint16_t)lo | ((uint16_t)hi << 8);
        uint8_t priv     = kc & 0x01;
        uint8_t pub_info = (kc >> 1) & 0x01;
        uint8_t key_type = (kc >> 2) & 0x07;
        uint8_t lockable = (kc >> 5) & 0x01;
        const char *kt_str = (key_type == 4) ? "P-256  " :
                             (key_type == 7) ? "No-ECC" : "RFU    ";
        printf("  %2d    0x%04X   %-7s  %-7s  %-7s  %s\n",
               s, kc,
               priv     ? "YES" : "NO",
               kt_str,
               pub_info ? "YES" : "NO",
               lockable ? "YES" : "NO");
    }

    printf("\n[ Hex dump (128 bytes) ]\n");
    for (int i = 0; i < 128; i++) 
    {
        if (i % 16 == 0) printf("  [%02X] ", i);
        printf("%02X ", cfg[i]);
        if (i % 16 == 15) printf("\n");
    }
    printf("\n============================================================\n\n");
}

static int verify_config_matches(const uint8_t cfg[CONFIG_ZONE_SIZE]) 
{
/* Target values ​​– must match TARGET_SLOT_CONFIG/KEY_CONFIG in the firmware. * 
* ENDIANNESS (datasheet section 4.1): 
* SlotConfig and KeyConfig are 16-bit words stored in little-endian EEPROM: 
* cfg[20 + slot*2] = byte LOW (bits 7:0) 
* cfg[20 + slot*2 + 1] = byte HIGH (bits 15:8) 
* 
* SlotConfig ECC = 0x2087 → LO=0x87, HI=0x20 
* KeyConfig ECC = 0x0033 → LO=0x33, HI=0x00 
* SlotConfig DAT = 0x00AF → LO=0xAF, HI=0x00 
* KeyConfig DAT = 0x001C → LO=0x1C, HI=0x00 
* 
* We compare byte by byte (we do not convert to uint16_t before comparing).
* For display, we compose uint16_t with lo|(hi<<8) to show the logical value.
*/
    static const uint8_t ECC_SC_LO = 0x87, ECC_SC_HI = 0x20; /* SlotConfig ECC = 0x2087 */
    static const uint8_t DAT_SC_LO = 0x0F, DAT_SC_HI = 0x00; /* SlotConfig DAT = 0x00AF */
    static const uint8_t ECC_KC_LO = 0x33, ECC_KC_HI = 0x00; /* KeyConfig  ECC = 0x0033 */
    static const uint8_t DAT_KC_LO = 0x1C, DAT_KC_HI = 0x00; /* KeyConfig  DAT = 0x001C */

    int errors = 0;

    printf("\n[ Verification of configuration ]\n");

    for (int s = 0; s < 16; s++) 
    {
        uint8_t sc_lo = cfg[CONFIG_OFFSET_SLOT_CFG + s * 2];
        uint8_t sc_hi = cfg[CONFIG_OFFSET_SLOT_CFG + s * 2 + 1];
        uint8_t kc_lo = cfg[CONFIG_OFFSET_KEY_CFG + s * 2];
        uint8_t kc_hi = cfg[CONFIG_OFFSET_KEY_CFG + s * 2 + 1];

        uint8_t exp_sc_lo = (s <= 7) ? ECC_SC_LO : DAT_SC_LO;
        uint8_t exp_sc_hi = (s <= 7) ? ECC_SC_HI : DAT_SC_HI;
        uint8_t exp_kc_lo = (s <= 7) ? ECC_KC_LO : DAT_KC_LO;
        uint8_t exp_kc_hi = (s <= 7) ? ECC_KC_HI : DAT_KC_HI;

        if (sc_lo != exp_sc_lo || sc_hi != exp_sc_hi) 
        {
            uint16_t actual = (uint16_t)sc_lo  | ((uint16_t)sc_hi  << 8);
            uint16_t expect = (uint16_t)exp_sc_lo | ((uint16_t)exp_sc_hi << 8);
            printf("  MISMATCH SlotConfig[%2d]: have 0x%04X, expect 0x%04X"
                   "  (raw bytes: have [LO=%02X HI=%02X], expect [LO=%02X HI=%02X])\n",
                   s, actual, expect, sc_lo, sc_hi, exp_sc_lo, exp_sc_hi);
            errors++;
        }

        if (kc_lo != exp_kc_lo || kc_hi != exp_kc_hi) 
        {
            uint16_t actual = (uint16_t)kc_lo  | ((uint16_t)kc_hi  << 8);
            uint16_t expect = (uint16_t)exp_kc_lo | ((uint16_t)exp_kc_hi << 8);
            printf("  MISMATCH KeyConfig [%2d]: have 0x%04X, expect 0x%04X"
                   "  (raw bytes: have [LO=%02X HI=%02X], expect [LO=%02X HI=%02X])\n",
                   s, actual, expect, kc_lo, kc_hi, exp_kc_lo, exp_kc_hi);
            errors++;
        }
    }

    if (cfg[18] != 0xAA) 
    {
        printf("  MISMATCH OTPmode [18]: have 0x%02X, expect 0xAA (Read-Only)\n",
               cfg[18]);
        errors++;
    }

    if (errors == 0) 
    {
        printf("  RESULT: OK – configuration matches the target.\n");
    } 
    else 
    {
        printf("  RESULT: ERROR – %d mismatches. DO NOT lock!\n", errors);
    }
    return errors;
}

int main(int argc, char *argv[]) 
{
    if (argc < 3) 
    {
        printf("Usage: %s <port> <command> [slot]\n", argv[0]);
        printf("\nCommands:\n");
        printf("  read         – read and display config zone\n");
        printf("  write        – write target configuration\n");
        printf("  verify       – compare with target\n");
        printf("  lock-config  – lock config zone [IRREVERSIBLE]\n");
        printf("  lock-data    – lock data/OTP zone [IRREVERSIBLE]\n");
        printf("  genkey <N>   – generate ECC key in slot N (0-7)\n");
        printf("  keys         – show key status in slots 0-7\n");
        printf("\nSafe sequence:\n");
        printf("  1. read → 2. write → 3. verify → 4. read → 5. lock-config\n");
        printf("  6. genkey 0 → 7. keys → 8. lock-data\n");
        return 1;
    }

    const char *port = argv[1];
    const char *cmd  = argv[2];

    int fd = device_open(port);
    if (fd < 0) 
    {
        fprintf(stderr, "Error: cannot open port %s\n", port);
        return 1;
    }

    uint8_t resp[256];
    uint16_t resp_len = 0;
    int ret = 0;

    /* ------------------------------------------------------------------ */
    if (strcmp(cmd, "read") == 0) 
    {
        printf("[*] Reading config zone...\n");
        uint8_t req = OP_READ_CONFIG;
        if (device_send_cmd(fd, CMD_CONFIG_OP, &req, 1, NULL, resp, &resp_len) != 0) {
            fprintf(stderr, "Error: communication error\n");
            ret = 1;
        } 
        else if (resp_len != CONFIG_ZONE_SIZE) 
        {
            fprintf(stderr, "Error: received %u bytes, expected %d\n",
                    resp_len, CONFIG_ZONE_SIZE);
            ret = 1;
        } 
        else 
        {
            print_config_zone(resp);
        }

    /* ------------------------------------------------------------------ */
    } 
    else if (strcmp(cmd, "write") == 0) 
    {
        printf("[*] Writing target configuration...\n");
        printf("    Slots 0-7:  ECC P-256, ECDH in clear, GenKey allowed\n");
        printf("    Sloty 8-15: Dane publiczne, zawsze dostepne\n");

        /* Najpierw odczytaj i sprawdź czy config jest odblokowana */
        uint8_t req_r = OP_READ_CONFIG;
        if (device_send_cmd(fd, CMD_CONFIG_OP, &req_r, 1, NULL, resp, &resp_len) == 0
            && resp_len == CONFIG_ZONE_SIZE) 
        {
            if (resp[CONFIG_OFFSET_LOCK_CFG] != ZONE_UNLOCKED) 
            {
                fprintf(stderr, "Error: Config zone is already locked!\n");
                ret = 1;
                goto done;
            }
        }

        uint8_t req_w = OP_WRITE_CONFIG;
        uint8_t result[4];
        uint16_t result_len = 0;
        if (device_send_cmd(fd, CMD_CONFIG_OP, &req_w, 1, NULL, result, &result_len) != 0) 
        {
            fprintf(stderr, "Error: failed to write configuration\n");
            ret = 1;
        } 
        else 
        {
            printf("[OK] Write completed. Run 'verify' to check.\n");
        }

    /* ------------------------------------------------------------------ */
    } 
    else if (strcmp(cmd, "verify") == 0) 
    {
        printf("[*] Verifying configuration...\n");
        uint8_t req = OP_READ_CONFIG;
        if (device_send_cmd(fd, CMD_CONFIG_OP, &req, 1, NULL, resp, &resp_len) != 0
            || resp_len != CONFIG_ZONE_SIZE) 
        {
            fprintf(stderr, "Error: failed to read configuration\n");
            ret = 1;
        } 
        else 
        {
            int errors = verify_config_matches(resp);
            ret = (errors > 0) ? 1 : 0;
        }

    /* ------------------------------------------------------------------ */
    } 
    else if (strcmp(cmd, "lock-config") == 0) 
    {
        printf("[*] LOCKING CONFIG ZONE\n");
        printf("[!] This is an IRREVERSIBLE operation.\n");
        printf("[!] Make sure 'verify' returned OK.\n");
        printf("[?] Enter 'LOCK' to confirm: ");
        fflush(stdout);
        char confirm_buf[16];
        if (fgets(confirm_buf, sizeof(confirm_buf), stdin) == NULL ||
            strncmp(confirm_buf, "LOCK", 4) != 0) 
        {
            printf("Operation cancelled.\n");
            ret = 0;
            goto done;
        }

        uint8_t req_r = OP_READ_CONFIG;
        if (device_send_cmd(fd, CMD_CONFIG_OP, &req_r, 1, NULL, resp, &resp_len) == 0
            && resp_len == CONFIG_ZONE_SIZE) 
        {
            int errors = verify_config_matches(resp);
            if (errors > 0) 
            {
                fprintf(stderr, "ABANDONED: configuration mismatch. Run 'write' first.\n");
                ret = 1;
                goto done;
            }
        }

        uint8_t req_l = OP_LOCK_CONFIG;
        uint8_t result[4];
        uint16_t result_len = 0;
        if (device_send_cmd(fd, CMD_CONFIG_OP, &req_l, 1, NULL, result, &result_len) != 0) 
        {
            fprintf(stderr, "Error: failed to lock config zone\n");
            ret = 1;
        } 
        else 
        {
            printf("[OK] Config zone LOCKED.\n");
            printf("[->] Next step: 'genkey 0'\n");
        }

    /* ------------------------------------------------------------------ */
    } 
    else if (strcmp(cmd, "lock-data") == 0) 
    {
        printf("[*] LOCKING DATA/OTP ZONE\n");
        printf("[!] This is an IRREVERSIBLE operation.\n");
        printf("[!] Make sure keys are generated ('keys').\n");
        printf("[?] Enter 'LOCK' to confirm: ");
        fflush(stdout);
        char confirm_buf[16];
        if (fgets(confirm_buf, sizeof(confirm_buf), stdin) == NULL ||
            strncmp(confirm_buf, "LOCK", 4) != 0) 
        {
            printf("Operation cancelled.\n");
            ret = 0;
            goto done;
        }

        uint8_t req_l = OP_LOCK_DATA;
        uint8_t result[4];
        uint16_t result_len = 0;
        if (device_send_cmd(fd, CMD_CONFIG_OP, &req_l, 1, NULL, result, &result_len) != 0) 
        {
            fprintf(stderr, "Error: failed to lock data zone\n");
            ret = 1;
        } 
        else 
        {
            printf("[OK] Data/OTP zone LOCKED. Device ready.\n");
        }

    /* ------------------------------------------------------------------ */
    } 
    else if (strcmp(cmd, "genkey") == 0) 
    {
        if (argc < 4) 
        {
            fprintf(stderr, "Error: specify slot number: %s %s genkey <0-7>\n",
                    argv[0], port);
            ret = 1;
            goto done;
        }

        int slot = atoi(argv[3]);
        if (slot < 0 || slot > 7) 
        {
            fprintf(stderr, "Error: slot must be 0-7\n");
            ret = 1;
            goto done;
        }

        printf("[*] Generating ECC P-256 key in slot %d...\n", slot);
        printf("[!] WARNING: existing key in slot %d will be overwritten!\n", slot);
        printf("[?] Continue? [y/N]: ");
        fflush(stdout);
        char ans[4];
        if (fgets(ans, sizeof(ans), stdin) == NULL ||
            (ans[0] != 'y' && ans[0] != 'Y')) 
        {
            printf("Operation cancelled.\n");
            ret = 0;
            goto done;
        }

        uint8_t req[1] = { (uint8_t)slot };
        uint8_t pubkey[64];
        uint16_t pk_len = 0;
        uint8_t gen_resp[64];
        uint16_t gen_len = 0;
        int gen_ret = device_send_cmd(fd, CMD_GEN_KEY, req, 1, NULL, gen_resp, &gen_len);

        if (gen_ret != 0 || gen_len != 64) 
        {
            if (gen_len == 1) 
            {
                /* Debug: firmware zwrócił kod błędu ATCA */
                uint8_t atca_status = gen_resp[0];
                const char *meaning =
                    atca_status == 0x0F ? "EXECUTION_ERROR (data zone not locked?)" :
                    atca_status == 0x03 ? "PARSE_ERROR (wrong slot or parameters)" :
                    atca_status == 0x05 ? "ECC_FAULT (try again)" :
                    atca_status == 0xD4 ? "GEN_FAIL (slot not configured as ECC?)" :
                    atca_status == 0xF4 ? "WAKE_FAILED (I2C problem)" :
                    atca_status == 0xFF ? "COMM_FAIL (I2C communication problem)" :
                    "unknown";
                fprintf(stderr, "ATCA Error: 0x%02X – %s\n", atca_status, meaning);
            } 
            else 
            {
                fprintf(stderr, "Error generating key (len=%u)\n", gen_len);
            }
            ret = 1;
        } 
        else 
        {
            memcpy(pubkey, gen_resp, 64);
            printf("[OK] Key generated in slot %d.\n", slot);
            printf("  Public Key X: ");
            for (int i = 0; i < 32; i++) printf("%02X", pubkey[i]);
            printf("\n  Public Key Y: ");
            for (int i = 32; i < 64; i++) printf("%02X", pubkey[i]);
            printf("\n");
        }

    /* ------------------------------------------------------------------ */
    } 
    else if (strcmp(cmd, "keys") == 0) 
    {
        printf("[*] Checking ECC key status (slots 0-7)...\n");
        printf("\n  Slot  Status        Public Key X (first 16B)\n");
        printf("  -----------------------------------------------------------\n");
        for (int s = 0; s <= 7; s++) 
        {
            uint8_t req[1] = { (uint8_t)s };
            uint8_t pubkey[64];
            uint16_t pk_len = 0;
            if (device_send_cmd(fd, CMD_GET_PUBLIC_KEY, req, 1, NULL, pubkey, &pk_len) == 0
                && pk_len == 64) 
            {
                printf("  %2d    %-12s ", s, "EXISTS");
                for (int i = 0; i < 16; i++) printf("%02X", pubkey[i]);
            } 
            else 
            {
                printf("  %2d    pusty\n", s);
            }
        }
        printf("\n");

    /* ------------------------------------------------------------------ */
    } 
    else 
    {
        fprintf(stderr, "Unknown command: %s\n", cmd);
        ret = 1;
    }

done:
    device_close(fd);
    return ret;
}
