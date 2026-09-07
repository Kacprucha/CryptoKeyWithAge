#include "decrypt.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <mbedtls/nist_kw.h>

#include "../pgp/pkesk.h"
#include "../pgp/kdf.h"
#include "../device/device.h"
#include "../device/protocol.h"
#include "../device/device_tup.h"
#include "../benchmarks/timing.h"

int cmd_decrypt(int argc, char *argv[])
{
    const char *input_path = NULL;
    const char *port = "/dev/ttyACM0";
    const char *fp_path = NULL;
    const char *output_path = NULL;
    int slot = 0;
    bool logger_enabled = true;
    bool skip_tup = false;
 
    for (int i = 0; i < argc; i++) 
    {
        if (strcmp(argv[i], "--port") == 0 && i + 1 < argc) 
        {
            port = argv[++i];
        }
        else if (strcmp(argv[i], "--slot") == 0 && i + 1 < argc) 
        {
            slot = atoi(argv[++i]);
        }
        else if (strcmp(argv[i], "--skipp-tup") == 0 && i + 1 < argc) 
        {
            skip_tup = strcmp(argv[++i], "true") == 0;
        }
        else if (strcmp(argv[i], "--fp") == 0 && i + 1 < argc) 
        {
            fp_path = argv[++i];
        }
        else if (strcmp(argv[i], "--output") == 0 && i + 1 < argc)
        {
            output_path = argv[++i];
        }
        else if (strcmp(argv[i], "--logger") == 0) 
        {
            logger_enabled = strcmp(argv[++i], "true") == 0;
        }
        else if (argv[i][0] != '-' && input_path == NULL)
        {
            input_path = argv[i];
        }
    }
 
    if (!input_path) 
    {
        fprintf(stderr, "Usage: pico-pgp decrypt <file.pgp> [--slot N] [--port DEV] [--fp file.fp] [--output file]\n");
        return 1;
    }
 
    /* Loading fingerprint subkey (20B) from .fp file */
    uint8_t fingerprint[20] = {0};
    char fp_auto[512];
    if (!fp_path) 
    {
        snprintf(fp_auto, sizeof(fp_auto), "pico_cert.pgp.fp");
        fp_path = fp_auto;
    }
    
    FILE *fp_file = fopen(fp_path, "rb");
    if (!fp_file) 
    {
        fprintf(stderr,
            "Error: fingerprint file not found: %s\n"
            "Run first: python3 gen_cert.py\n"
            "Then:      gpg --import pico_cert.pgp\n",
            fp_path);
        return 1;
    }

    size_t fp_read = fread(fingerprint, 1, 20, fp_file);
    fclose(fp_file);
    if (fp_read != 20) 
    {
        fprintf(stderr, "Error: fingerprint file must be exactly 20B, got %zu\n", fp_read);
        return 1;
    }
 
    if (logger_enabled) 
    {
        printf("[*] Fingerprint: ");
        
        for (int i = 0; i < 20; i++) 
        {
            printf("%02x", fingerprint[i]);
        }
        
        printf("\n");
 
        printf("[*] Connecting to Pico on %s...\n", port);
    }

    int fd = device_open(port);
    if (fd < 0) 
    { 
        perror("device_open"); 
        return 1; 
    }

    int ret = pgp_decrypt_core(fd, input_path, output_path, slot, fingerprint, skip_tup, NULL, logger_enabled, NULL);

    device_close(fd);
    return ret;
}

int pgp_decrypt_core(int fd, const char *input_path, const char *output_path, int slot, const uint8_t fingerprint[20], bool skip_tup,
                     pgp_secret_cache_t *cache, bool logger_enabled, double *out_time_ms)
{
    double t0 = now_ms();

    FILE *f = fopen(input_path, "rb");
    if (!f) 
    { 
        perror("fopen"); 
        return 1; 
    }
    
    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    rewind(f);
    
    uint8_t *pgp_data = malloc((size_t)fsize);
    if (!pgp_data) 
    { 
        fclose(f); 
        return 1; 
    }
    
    fread(pgp_data, 1, (size_t)fsize, f);
    fclose(f);
 
    /* Parsing PKESK - extracting eph_pub and encrypted_sk */
    pkesk_t pkesk;
    if (pkesk_parse(pgp_data, (size_t)fsize, &pkesk) != 0) 
    {
        fprintf(stderr, "PKESK parsing error\n");
        free(pgp_data);
        return 1;
    }
 
    if (logger_enabled) 
    {
        printf("[*] PKESK parsed OK\n");
        printf("\teph_pub X: ");
    
        for (int i = 0; i < 32; i++) 
        { 
            printf("%02x", pkesk.eph_pub_xy[i]);
        }

        printf("\n\teph_pub Y: ");
    
        for (int i = 0; i < 32; i++) 
        {
            printf("%02x", pkesk.eph_pub_xy[32 + i]);
        }
        
        printf("\n");
    }
 
    free(pgp_data);
    
    uint8_t shared_secret[32];

    if (cache && cache->have_secret) 
    {
        memcpy(shared_secret, cache->shared, 32);
    } 
    else 
    {
        uint8_t ecdh_payload[65];
        ecdh_payload[0] = (uint8_t)slot;
        memcpy(ecdh_payload + 1, pkesk.eph_pub_xy, 64);

        uint16_t ss_len = 0;
        int ecdh_ok;

        if (skip_tup) 
        {
            int rc = device_send_cmd(fd, CMD_ECDH_REQUEST_BYPASS_TUP, ecdh_payload, 65, NULL, shared_secret, &ss_len);
            
            ecdh_ok = (rc == 0 && ss_len == 32) ? 0 : -1;
        } 
        else 
        {
            int tup_rc = pgp_device_send_cmd_tup(fd, CMD_ECDH_REQUEST, ecdh_payload, 65, shared_secret, &ss_len);

            ecdh_ok = (tup_rc == 0 && ss_len == 32) ? 0 : -1;
        }

        if (ecdh_ok != 0) 
        {
            return 1;
        }

        if (cache) 
        {                    
            memcpy(cache->shared, shared_secret, 32);
            cache->have_secret = 1;
        }
    }


    if (logger_enabled) 
    {
        printf("[*] Hardware ECDH OK\n\tshared_secret: "); 
    
        for(int i=0;i<32;i++) 
        {
            printf("%02x",shared_secret[i]);
        }

        printf("\n");
    }

    uint8_t wrapping_key[16];
    pgp_ecdh_kdf(shared_secret, fingerprint, wrapping_key);
    
    if (logger_enabled) 
    {
        printf("[*] KDF OK\n");
    }
 
    mbedtls_nist_kw_context kw;
    mbedtls_nist_kw_init(&kw);
    mbedtls_nist_kw_setkey(&kw, MBEDTLS_CIPHER_ID_AES, wrapping_key, 128, 0);
 
    uint8_t session_key_blob[64];  
    size_t  blob_len = 0;
    int kw_ret = mbedtls_nist_kw_unwrap(&kw, MBEDTLS_KW_MODE_KW, pkesk.encrypted_sk, pkesk.encrypted_sk_len, session_key_blob, &blob_len, sizeof(session_key_blob));
    mbedtls_nist_kw_free(&kw);
 
    if (kw_ret != 0) 
    {
        fprintf(stderr,
            "Error: AES Key Unwrap (code: -0x%04X)\n"
            "Possible causes:\n"
            "  - Wrong slot (use --slot N)\n"
            "  - Invalid fingerprint (check pico_cert.pgp.fp)\n"
            "  - File .pgp is not encrypted with this key\n",
            (unsigned)(-kw_ret));
        return 1;
    }
 
    uint8_t algo_id  = session_key_blob[0];
    uint8_t *sess_key = session_key_blob + 1;
    size_t   sess_key_len;
 
    switch (algo_id) 
    {
        case 0x07: 
            sess_key_len = 16;  /* AES-128 */
            break; 
        
        case 0x08: 
            sess_key_len = 24; /* AES-192 */
            break;  

        case 0x09: 
            sess_key_len = 32; /* AES-256 */
            break;  

        default:
            fprintf(stderr, "Error: unknown symmetric algo_id: 0x%02x\nExpected 0x07 (AES-128), 0x08 (AES-192), or 0x09 (AES-256)\n", algo_id);
            return 1;
    }
 
    if (logger_enabled) 
    {
        printf("[*] AES Key Unwrap OK\n");
        printf("\talgo_id: 0x%02x (AES-%zu)\n", algo_id, sess_key_len * 8);
        printf("\tsession_key: ");
    
        for (size_t i = 0; i < sess_key_len; i++) 
        {
            printf("%02x", sess_key[i]);
        }
        
        printf("\n");
    }

    uint32_t ck_computed = 0;
    
    for (size_t i = 0; i < sess_key_len; i++) 
    {
        ck_computed += sess_key[i];
    }

    ck_computed &= 0xFFFF;
    uint16_t ck_stored = ((uint16_t)sess_key[sess_key_len] << 8) | (uint16_t)sess_key[sess_key_len + 1];
    if (ck_computed != ck_stored) 
    {
        fprintf(stderr,
            "Warning: session key checksum mismatch "
            "(computed=%04x stored=%04x)\n"
            "Proceeding anyway — GPG will verify integrity via MDC.\n",
            ck_computed, ck_stored);
    }
 
    /* Decrypting via GPG with --override-session-key*/
    /* Building a hex string session key */
    char sk_hex[2 * 32 + 1];
    memset(sk_hex, 0, sizeof(sk_hex));
    for (size_t i = 0; i < sess_key_len; i++) 
    {
        sprintf(sk_hex + 2 * i, "%02x", sess_key[i]);
    }
 

    char out_path[512];
    if (output_path) 
    {
        snprintf(out_path, sizeof(out_path), "%s", output_path);
    } 
    else 
    {
        size_t in_len = strlen(input_path);
        if (in_len > 4 && strcmp(input_path + in_len - 4, ".pgp") == 0) 
        {
            snprintf(out_path, sizeof(out_path), "%.*s.dec", (int)(in_len - 4), input_path);
        } else 
        {
            snprintf(out_path, sizeof(out_path), "%s.dec", input_path);
        }
    }

    char gpg_cmd[2048];
    snprintf(gpg_cmd, sizeof(gpg_cmd),
        "gpg --override-session-key \"%d:%s\" "
        "    --output \"%s\" "
        "    --batch --yes "
        "    --decrypt \"%s\"",
        (int)algo_id,
        sk_hex,
        out_path,
        input_path);    
 
    if (logger_enabled) 
    {
        printf("[*] Decrypting via GPG (AES-CFB + MDC verification)...\n");
    }
 
    int ret = system(gpg_cmd);
    
    if (ret != 0) 
    {
        fprintf(stderr, "Error: GPG decryption failed (exit code %d)\nCommand: %s\n", ret, gpg_cmd);
        return 1;
    }
 
    if (logger_enabled) 
    {
        printf("[+] Decrypted: %s\n", out_path);
    }

    if (out_time_ms) 
    {
        *out_time_ms = now_ms() - t0;   
    }

    return 0;
}