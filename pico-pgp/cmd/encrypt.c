#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cmd_common.h"

#include "../pgp/kdf.h"
#include "../pgp/keywrap.h"
#include "../pgp/seipd.h"
#include "../pgp/packet.h"

#include "../device/device.h"
#include "../device/protocol.h"

#include <mbedtls/ecp.h>
#include <mbedtls/bignum.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>


typedef struct 
{
    const char *input_file;
    int slot; /* default 0 */
    const char *port; /* default /dev/ttyACM0 */
    int verbose;
} encrypt_args_t;

static int parse_encrypt_args(int argc, char *argv[], encrypt_args_t *args)
{
    args->input_file = NULL;
    args->slot = 0;
    args->port = "/dev/ttyACM0";
    args->verbose = 0;

    for (int i = 1; i < argc; i++) 
    {
        if (strcmp(argv[i], "--slot") == 0 && i + 1 < argc) 
        {
            args->slot = atoi(argv[++i]);
            if (args->slot < 0 || args->slot > 7) 
            {
                fprintf(stderr, "Error: slot must be 0-7\n");
                return -1;
            }
        } 
        else if (strcmp(argv[i], "--port") == 0 && i + 1 < argc) 
        {
            args->port = argv[++i];
        } 
        else if (strcmp(argv[i], "--verbose") == 0 || strcmp(argv[i], "-v") == 0) 
        {
            args->verbose = 1;
        } 
        else if (argv[i][0] != '-') 
        {
            args->input_file = argv[i];
        } 
        else 
        {
            fprintf(stderr, "Unknown option: %s\n", argv[i]);
            return -1;
        }
    }

    if (!args->input_file) 
    {
        fprintf(stderr, "Usage: pico-pgp encrypt <plik> [--slot N] [--port /dev/ttyACM0]\n");
        return -1;
    }
    return 0;
}

typedef struct 
{
    mbedtls_ecp_group grp;
    mbedtls_mpi d; /* private key */
    mbedtls_ecp_point Q; /* public key = d × G */
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
} eph_ctx_t;

static int eph_generate(eph_ctx_t *ctx, uint8_t eph_pub_xy[64])
{
    mbedtls_ecp_group_init(&ctx->grp);
    mbedtls_mpi_init(&ctx->d);
    mbedtls_ecp_point_init(&ctx->Q);
    mbedtls_entropy_init(&ctx->entropy);
    mbedtls_ctr_drbg_init(&ctx->ctr_drbg);

    int rc = mbedtls_ctr_drbg_seed(&ctx->ctr_drbg, mbedtls_entropy_func, &ctx->entropy, (const uint8_t *)"pico-pgp-enc", 12);
    if (rc != 0) return rc;

    /* Load curve P-256 */
    rc = mbedtls_ecp_group_load(&ctx->grp, MBEDTLS_ECP_DP_SECP256R1);
    if (rc != 0) return rc;

    /* Generate random private key d ∈ [1, n-1] */
    rc = mbedtls_ecp_gen_privkey(&ctx->grp, &ctx->d, mbedtls_ctr_drbg_random, &ctx->ctr_drbg);
    if (rc != 0) return rc;

    /* Calculate public key Q = d × G */
    rc = mbedtls_ecp_mul(&ctx->grp, &ctx->Q, &ctx->d, &ctx->grp.G, mbedtls_ctr_drbg_random, &ctx->ctr_drbg);
    if (rc != 0) return rc;

    /*
     * Export Q as uncompressed point: 0x04 || X[32] || Y[32] (65B)
     * Skipping the first byte (0x04) and take the remaining 64B as X||Y
     */
    uint8_t pub_buf[65];
    size_t  pub_len = 0;
    rc = mbedtls_ecp_point_write_binary(&ctx->grp, &ctx->Q, MBEDTLS_ECP_PF_UNCOMPRESSED, &pub_len, pub_buf, sizeof(pub_buf));
    if (rc != 0 || pub_len != 65) return (rc != 0) ? rc : -1;

    /* buf[0] = 0x04 (prefix uncompressed), buf[1..32] = X, buf[33..64] = Y */
    memcpy(eph_pub_xy,      pub_buf + 1,  32); /* X */
    memcpy(eph_pub_xy + 32, pub_buf + 33, 32); /* Y */

    return 0;
}

static void eph_free(eph_ctx_t *ctx)
{
    mbedtls_ecp_group_free(&ctx->grp);
    mbedtls_mpi_free(&ctx->d);
    mbedtls_ecp_point_free(&ctx->Q);
    mbedtls_ctr_drbg_free(&ctx->ctr_drbg);
    mbedtls_entropy_free(&ctx->entropy);
}

static int ecdh_compute_shared(eph_ctx_t *ctx, const uint8_t *recipient_xy64, uint8_t shared_secret[32])
{
    uint8_t recip_buf[65];
    recip_buf[0] = 0x04;
    memcpy(recip_buf + 1, recipient_xy64, 64);

    mbedtls_ecp_point recip_Q;
    mbedtls_ecp_point_init(&recip_Q);

    int rc = mbedtls_ecp_point_read_binary(&ctx->grp, &recip_Q, recip_buf, sizeof(recip_buf));
    if (rc != 0) 
    {
        fprintf(stderr, "Error: Reading recipient's public key (%d)\n", rc);
        mbedtls_ecp_point_free(&recip_Q);
        return rc;
    }

    rc = mbedtls_ecp_check_pubkey(&ctx->grp, &recip_Q);
    if (rc != 0) 
    {
        fprintf(stderr, "Error: recipient's public key does not lie on the P-256 curve (%d)\n", rc);
        mbedtls_ecp_point_free(&recip_Q);
        return rc;
    }

    mbedtls_ecp_point result;
    mbedtls_ecp_point_init(&result);

    rc = mbedtls_ecp_mul(&ctx->grp, &result, &ctx->d, &recip_Q, mbedtls_ctr_drbg_random, &ctx->ctr_drbg);
    mbedtls_ecp_point_free(&recip_Q);

    if (rc != 0) 
    {
        mbedtls_ecp_point_free(&result);
        return rc;
    }

    uint8_t result_buf[65];
    size_t  result_len = 0;
    rc = mbedtls_ecp_point_write_binary(&ctx->grp, &result, MBEDTLS_ECP_PF_UNCOMPRESSED, &result_len, result_buf, sizeof(result_buf));
    mbedtls_ecp_point_free(&result);

    if (rc != 0 || result_len != 65) 
    {
        return (rc != 0) ? rc : -1;
    }

    memcpy(shared_secret, result_buf + 1, 32);
    
    return 0;
}

void cmd_encrypt(int argc, char *argv[])
{
    encrypt_args_t args;
    if (parse_encrypt_args(argc, argv, &args) != 0) 
    {
        return;
    }

    size_t   pt_len = 0;
    uint8_t *plaintext = read_file(args.input_file, &pt_len);
    if (!plaintext) 
    {
        fprintf(stderr, "Error: Cannot open file '%s'\n", args.input_file);
        return;
    }

    if (args.verbose) 
    {
        fprintf(stderr, "Loaded %zu B from '%s'\n", pt_len, args.input_file);
    }

    int fd = device_open(args.port);
    if (fd < 0) 
    {
        fprintf(stderr, "Error: unable to open port '%s'\n", args.port);
        free(plaintext);
        return;
    }

    uint8_t  recipient_pub[64];
    uint16_t pub_len = 0;

    uint8_t slot_byte = (uint8_t)args.slot;
    if (device_send_cmd(fd, CMD_GET_PUBLIC_KEY, &slot_byte, 1, NULL, recipient_pub, &pub_len) != 0 || pub_len != 64) 
    {
        fprintf(stderr, "Error: Unable to read key from slot %d\n", args.slot);
        device_close(fd);
        free(plaintext);
        return;
    }

    device_close(fd);

    if (args.verbose) 
    {
        dump_hex("recipient_pub[0..7]", recipient_pub, 8);
    }

    uint8_t fingerprint[20];
    compute_fingerprint(recipient_pub, fingerprint);

    if (args.verbose) 
    {
        dump_hex("fingerprint", fingerprint, 20);
    }

    eph_ctx_t eph;
    uint8_t   eph_pub_xy[64];

    if (eph_generate(&eph, eph_pub_xy) != 0) 
    {
        fprintf(stderr, "Error: Generating ephemeral key\n");
        free(plaintext);
        return;
    }

    if (args.verbose) 
    {
        dump_hex("eph_pub[0..7]", eph_pub_xy, 8);
    }

    uint8_t shared_secret[32];

    if (ecdh_compute_shared(&eph, recipient_pub, shared_secret) != 0) 
    {
        fprintf(stderr, "Error: calculating shared_secret\n");
        eph_free(&eph);
        free(plaintext);
        return;
    }

    eph_free(&eph);

    if (args.verbose) 
    {
        dump_hex("shared_secret[0..7]", shared_secret, 8);
    }

    uint8_t wrapping_key[32];

    if (pgp_ecdh_kdf(shared_secret, fingerprint, wrapping_key) != 0) 
    {
        fprintf(stderr, "Error: KDF\n");
        free(plaintext);
        return;
    }

    memset(shared_secret, 0, sizeof(shared_secret));

    uint8_t session_key[32];
    {
        mbedtls_entropy_context   ent;
        mbedtls_ctr_drbg_context  rng;
        
        mbedtls_entropy_init(&ent);
        mbedtls_ctr_drbg_init(&rng);
        
        mbedtls_ctr_drbg_seed(&rng, mbedtls_entropy_func, &ent, (const uint8_t *)"session-key", 11);
        mbedtls_ctr_drbg_random(&rng, session_key, 32);
        
        mbedtls_ctr_drbg_free(&rng);
        mbedtls_entropy_free(&ent);
    }

    uint8_t wrapped_sk[40];

    if (aes256_key_wrap(wrapping_key, session_key, wrapped_sk) != 0) 
    {
        fprintf(stderr, "Error: AES Key Wrap\n");
        free(plaintext);
        return;
    }

    memset(wrapping_key, 0, sizeof(wrapping_key));

    uint8_t *ciphertext = NULL;
    size_t   ct_len     = 0;

    if (seipd_encrypt(session_key, plaintext, pt_len, &ciphertext, &ct_len) != 0) 
    {
        fprintf(stderr, "Error: SEIPD encrypt\n");
        free(plaintext);
        return;
    }

    free(plaintext);

    memset(session_key, 0, sizeof(session_key));

    if (args.verbose) 
    {
        fprintf(stderr, "SEIPD ciphertext: %zu B\n", ct_len);
    }

    uint8_t key_id[8];
    memcpy(key_id, fingerprint + 12, 8);

    /* PKESK */
    uint8_t pkesk_buf[256];
    size_t  pkesk_len = 0;

    if (packet_write_pkesk(key_id, eph_pub_xy, wrapped_sk, pkesk_buf, &pkesk_len) != 0) 
    {
        fprintf(stderr, "Error: PKESK building\n");
        free(ciphertext);
        return;
    }

    /* SEIPD */
    uint8_t *seipd_buf = malloc(ct_len + 8);
    
    if (!seipd_buf) 
    {
        free(ciphertext);
        return;
    }
    
    size_t seipd_len = 0;

    if (packet_write_seipd(ciphertext, ct_len, seipd_buf, &seipd_len) != 0) 
    {
        fprintf(stderr, "Error: SEIPD building\n");
        free(ciphertext);
        free(seipd_buf);
        return;
    }
    free(ciphertext);

    char out_path[4096];
    snprintf(out_path, sizeof(out_path), "%s.pgp", args.input_file);

    size_t   total = pkesk_len + seipd_len;
    uint8_t *out   = malloc(total);
    
    if (!out) 
    {
        free(seipd_buf);
        return;
    }

    memcpy(out, pkesk_buf, pkesk_len);
    memcpy(out + pkesk_len, seipd_buf, seipd_len);
    free(seipd_buf);

    if (write_file(out_path, out, total) != 0) 
    {
        fprintf(stderr, "Error: file saving '%s'\n", out_path);
    } 
    else 
    {
        printf("Encrypted: %s  (%zu B → %zu B)\n", out_path, pt_len, total);
    }
    
    free(out);
}