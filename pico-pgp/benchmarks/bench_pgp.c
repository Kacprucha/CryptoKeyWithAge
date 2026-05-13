#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdint.h>

#include "../pgp/kdf.h"
#include "../pgp/keywrap.h"
#include "../pgp/seipd.h"
#include "../pgp/packet.h"
#include "../pgp/mpi.h"
#include "../device/device.h"
#include "../device/protocol.h"

#include <mbedtls/ecp.h>
#include <mbedtls/bignum.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/sha1.h>

#include <linux/time.h>

static const struct { const char *name; size_t size; } FILE_SIZES[] = {
    { "100B",   100 },
    { "1KB",    1024 },
    { "64KB",   64   * 1024 },
    { "1MB",    1024 * 1024 },
    { "10MB",   10   * 1024 * 1024 },
    { "100MB",  100  * 1024 * 1024 },
};
static const int N_SIZES = 6;

static double now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000.0 + ts.tv_nsec / 1e6;
}

static int cmp_double(const void *a, const void *b)
{
    double da = *(const double *)a;
    double db = *(const double *)b;
    return (da > db) - (da < db);
}

static double median_sorted(double *arr, int n)
{
    qsort(arr, (size_t)n, sizeof(double), cmp_double);
    return (n % 2 == 0)
        ? (arr[n/2 - 1] + arr[n/2]) / 2.0
        : arr[n/2];
}

typedef struct {
    mbedtls_ecp_group        grp;
    mbedtls_mpi              d;
    mbedtls_ecp_point        Q;
    mbedtls_entropy_context  entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
} eph_ctx_t;

static void eph_init(eph_ctx_t *ctx)
{
    mbedtls_ecp_group_init(&ctx->grp);
    mbedtls_mpi_init(&ctx->d);
    mbedtls_ecp_point_init(&ctx->Q);
    mbedtls_entropy_init(&ctx->entropy);
    mbedtls_ctr_drbg_init(&ctx->ctr_drbg);
    mbedtls_ctr_drbg_seed(&ctx->ctr_drbg, mbedtls_entropy_func, &ctx->entropy, (const uint8_t *)"bench", 5);
    mbedtls_ecp_group_load(&ctx->grp, MBEDTLS_ECP_DP_SECP256R1);
}

static void eph_free_ctx(eph_ctx_t *ctx)
{
    mbedtls_ecp_group_free(&ctx->grp);
    mbedtls_mpi_free(&ctx->d);
    mbedtls_ecp_point_free(&ctx->Q);
    mbedtls_ctr_drbg_free(&ctx->ctr_drbg);
    mbedtls_entropy_free(&ctx->entropy);
}

static int eph_gen(eph_ctx_t *ctx, uint8_t pub65[65])
{
    int rc;
    rc = mbedtls_ecp_gen_privkey(&ctx->grp, &ctx->d, mbedtls_ctr_drbg_random, &ctx->ctr_drbg);
    
    if (rc) 
    {
        return rc;
    }

    rc = mbedtls_ecp_mul(&ctx->grp, &ctx->Q, &ctx->d, &ctx->grp.G, mbedtls_ctr_drbg_random, &ctx->ctr_drbg);
    
    if (rc) 
    { 
        return rc;
    }

    size_t olen = 0;
    return mbedtls_ecp_point_write_binary(&ctx->grp, &ctx->Q, MBEDTLS_ECP_PF_UNCOMPRESSED, &olen, pub65, 65);
}

static int ecdh_soft(eph_ctx_t *ctx, const uint8_t *recip_xy64, uint8_t shared[32])
{
    uint8_t buf[65];
    buf[0] = 0x04;
    memcpy(buf + 1, recip_xy64, 64);

    mbedtls_ecp_point R, S;
    mbedtls_ecp_point_init(&R);
    mbedtls_ecp_point_init(&S);

    int rc = mbedtls_ecp_point_read_binary(&ctx->grp, &R, buf, 65);
    
    if (rc) 
    { 
        goto done; 
    }

    rc = mbedtls_ecp_mul(&ctx->grp, &S, &ctx->d, &R,  mbedtls_ctr_drbg_random, &ctx->ctr_drbg);
    
    if (rc) 
    { 
        goto done; 
    }

    uint8_t out[65]; size_t olen = 0;
    rc = mbedtls_ecp_point_write_binary(&ctx->grp, &S, MBEDTLS_ECP_PF_UNCOMPRESSED, &olen, out, 65);
    
    if (!rc) 
    {
        memcpy(shared, out + 1, 32);
    }

done:
    mbedtls_ecp_point_free(&R);
    mbedtls_ecp_point_free(&S);
    return rc;
}

typedef struct {
    size_t encrypted_bytes; /* total .pgp file size */
    size_t header_bytes; /* PKESK packet (cryptographic header) */
    size_t payload_bytes; /* SEIPD packet (encrypted data) */
    size_t overhead_bytes; /* encrypted_bytes - plaintext_bytes */
} pgp_sizes_t;

static pgp_sizes_t measure_pgp_size(eph_ctx_t *ctx, const uint8_t *recip_xy64, const uint8_t *fingerprint, const uint8_t *plaintext, size_t pt_len)
{
    pgp_sizes_t sz = {0};

    uint8_t shared[32], wrapping_key[32], session_key[32], wrapped_sk[40];
    eph_gen(ctx, (uint8_t[65]){0}); 

    uint8_t eph_pub65[65];
    eph_gen(ctx, eph_pub65);
    ecdh_soft(ctx, recip_xy64, shared);
    pgp_ecdh_kdf(shared, fingerprint, wrapping_key);
    mbedtls_ctr_drbg_random(&ctx->ctr_drbg, session_key, 32);
    aes256_key_wrap(wrapping_key, session_key, wrapped_sk);

    uint8_t *ct = NULL; size_t ct_len = 0;
    seipd_encrypt(session_key, plaintext, pt_len, &ct, &ct_len);

    uint8_t key_id[8];
    memcpy(key_id, fingerprint + 12, 8);

    uint8_t pkesk_buf[256]; size_t pkesk_len = 0; packet_write_pkesk(key_id, eph_pub65 + 1, wrapped_sk, pkesk_buf, &pkesk_len);

    uint8_t *seipd_buf = malloc(ct_len + 8); size_t seipd_len = 0;
    packet_write_seipd(ct, ct_len, seipd_buf, &seipd_len);

    sz.header_bytes = pkesk_len;
    sz.payload_bytes = seipd_len;
    sz.encrypted_bytes = pkesk_len + seipd_len;
    sz.overhead_bytes = sz.encrypted_bytes - pt_len;

    free(ct);
    free(seipd_buf);
    memset(shared, 0, 32);
    memset(wrapping_key, 0, 32);
    memset(session_key, 0, 32);

    return sz;
}

static void print_row(const char *name, double med, double mn, double mx, int n_runs, size_t pt_bytes, size_t enc_bytes, size_t overhead, size_t header, size_t payload)
{
    printf("%s,%.4f,%.4f,%.4f,%d,%zu,%zu,%zu,%zu,%zu\n", name, med, mn, mx, n_runs, pt_bytes, enc_bytes, overhead, header, payload);
}

/* ------------------------------------------------------------------ */
/*  Benchmark 1: ECDH Software                                        */
/* ------------------------------------------------------------------ */

static void bench_ecdh_soft(int n_runs, const uint8_t *recip_xy64)
{
    eph_ctx_t ctx;
    eph_init(&ctx);

    double *times = malloc((size_t)n_runs * sizeof(double));
    uint8_t shared[32];

    for (int i = 0; i < n_runs; i++) 
    {
        mbedtls_ecp_gen_privkey(&ctx.grp, &ctx.d, mbedtls_ctr_drbg_random, &ctx.ctr_drbg);
        mbedtls_ecp_mul(&ctx.grp, &ctx.Q, &ctx.d, &ctx.grp.G, mbedtls_ctr_drbg_random, &ctx.ctr_drbg);

        double t0 = now_ms();
        ecdh_soft(&ctx, recip_xy64, shared);
        times[i] = now_ms() - t0;
    }

    double med = median_sorted(times, n_runs);
    print_row("BenchmarkECDH_Software", med, times[0], times[n_runs-1], n_runs, 0, 0, 0, 0, 0);

    free(times);
    eph_free_ctx(&ctx);
}

/* ------------------------------------------------------------------ */
/*  Benchmark 2: ECDH Hardware                                        */
/* ------------------------------------------------------------------ */

static void bench_ecdh_hw(int n_runs, int fd, int slot)
{
    double *times = malloc((size_t)n_runs * sizeof(double));
    double *valid_t = malloc((size_t)n_runs * sizeof(double));
    int valid = 0;

    eph_ctx_t ctx;
    eph_init(&ctx);

    fprintf(stderr, "[bench_pgp] ECDH Hardware: %d iterations\n"
        "  Press TUP before each iteration, then ENTER.\n\n",
        n_runs);

    for (int i = 0; i < n_runs; i++) 
    {
        uint8_t eph65[65];
        eph_gen(&ctx, eph65);


        uint8_t payload[65];
        payload[0] = (uint8_t)slot;
        memcpy(payload + 1, eph65 + 1, 64);

        uint8_t resp_cmd = 0, resp[32] = {0};
        uint16_t resp_len = 0;
        device_send_cmd(fd, CMD_ECDH_REQUEST, payload, 65, &resp_cmd, resp, &resp_len);

        fprintf(stderr, "  [%d/%d] Press TUP, then ENTER: ",
                i + 1, n_runs);
        int ch; while ((ch = getchar()) != '\n' && ch != EOF);

        resp_cmd = 0; resp_len = 0;
        double t0 = now_ms();
        device_send_cmd(fd, CMD_ECDH_REQUEST, payload, 65, &resp_cmd, resp, &resp_len);
        times[i] = now_ms() - t0;

        if (resp_cmd != CMD_ECDH_REQUEST || resp_len != 32) 
        {
            fprintf(stderr, "  FAIL iteracja %d (cmd=0x%02X len=%u)\n", i, resp_cmd, resp_len);
            times[i] = -1.0;
        }
    }

    for (int i = 0; i < n_runs; i++) 
    {
        if (times[i] >= 0)  
        {
            valid_t[valid++] = times[i];
        }
    }

    if (valid > 0) 
    {
        double med = median_sorted(valid_t, valid);
        print_row("BenchmarkECDH_Hardware", med, valid_t[0], valid_t[valid-1], valid, 0, 0, 0, 0, 0);
    } 
    else 
    {
        fprintf(stderr, "[warn] No valid ECDH Hardware results\n");
    }

    free(times);
    free(valid_t);
    eph_free_ctx(&ctx);
}

/* ------------------------------------------------------------------ */
/*  Benchmark 3: Encrypt Software                                     */
/* ------------------------------------------------------------------ */

static void bench_encrypt_soft(int n_runs, const uint8_t *recip_xy64, const uint8_t *fingerprint)
{
    eph_ctx_t ctx;
    eph_init(&ctx);

    for (int s = 0; s < N_SIZES; s++) 
    {
        size_t   pt_len = FILE_SIZES[s].size;
        uint8_t *plain  = malloc(pt_len);

        for (size_t i = 0; i < pt_len; i++) 
        {
            plain[i] = (uint8_t)(i & 0xFF);
        }

        double *times = malloc((size_t)n_runs * sizeof(double));

        for (int i = 0; i < n_runs; i++) 
        {
            double t0 = now_ms();

            uint8_t shared[32], wrapping_key[32], session_key[32], wrapped_sk[40];
            uint8_t eph65[65];
            eph_gen(&ctx, eph65);
            ecdh_soft(&ctx, recip_xy64, shared);
            pgp_ecdh_kdf(shared, fingerprint, wrapping_key);
            mbedtls_ctr_drbg_random(&ctx.ctr_drbg, session_key, 32);
            aes256_key_wrap(wrapping_key, session_key, wrapped_sk);

            uint8_t *ct = NULL; size_t ct_len = 0;
            seipd_encrypt(session_key, plain, pt_len, &ct, &ct_len);

            times[i] = now_ms() - t0;

            free(ct);
            memset(shared, 0, 32);
            memset(wrapping_key, 0, 32);
            memset(session_key, 0, 32);
        }

        pgp_sizes_t sz = measure_pgp_size(&ctx, recip_xy64, fingerprint, plain, pt_len);

        char name[64];
        snprintf(name, sizeof(name), "BenchmarkEncrypt_Soft/%s", FILE_SIZES[s].name);

        double med = median_sorted(times, n_runs);
        print_row(name, med, times[0], times[n_runs-1], n_runs, pt_len, sz.encrypted_bytes, sz.overhead_bytes, sz.header_bytes, sz.payload_bytes);

        free(plain);
        free(times);
    }

    eph_free_ctx(&ctx);
}

/* ------------------------------------------------------------------ */
/*  Benchmark 4: Decrypt Software                                     */
/* ------------------------------------------------------------------ */

static void bench_decrypt_soft(int n_runs, const uint8_t *recip_xy64, const uint8_t *fingerprint)
{
    eph_ctx_t ctx;
    eph_init(&ctx);

    for (int s = 0; s < N_SIZES; s++) 
    {
        int runs = (FILE_SIZES[s].size >= 100 * 1024 * 1024) ? (n_runs > 5 ? 5 : n_runs) : n_runs;

        size_t pt_len = FILE_SIZES[s].size;
        uint8_t *plain = malloc(pt_len);
        
        for (size_t i = 0; i < pt_len; i++) 
        {
            plain[i] = (uint8_t)(i & 0xFF);
        }

        uint8_t shared[32], wrapping_key[32], session_key[32], wrapped_sk[40];
        uint8_t eph65[65];
        eph_gen(&ctx, eph65);
        ecdh_soft(&ctx, recip_xy64, shared);
        pgp_ecdh_kdf(shared, fingerprint, wrapping_key);
        mbedtls_ctr_drbg_random(&ctx.ctr_drbg, session_key, 32);
        aes256_key_wrap(wrapping_key, session_key, wrapped_sk);

        uint8_t *ct = NULL; size_t ct_len = 0;
        seipd_encrypt(session_key, plain, pt_len, &ct, &ct_len);

        double *times = malloc((size_t)runs * sizeof(double));

        for (int i = 0; i < runs; i++) 
        {
            double t0 = now_ms();

            uint8_t recovered_sk[32];
            aes256_key_unwrap(wrapping_key, wrapped_sk, recovered_sk);
            uint8_t *out = NULL; size_t out_len = 0;
            seipd_decrypt(recovered_sk, ct, ct_len, &out, &out_len);

            times[i] = now_ms() - t0;
            free(out);
        }

        char name[64];
        snprintf(name, sizeof(name), "BenchmarkDecrypt_Soft/%s", FILE_SIZES[s].name);

        double med = median_sorted(times, runs);

        size_t enc_total = ct_len + 120 + 3; 
        print_row(name, med, times[0], times[runs-1], runs, pt_len, enc_total, enc_total - pt_len, 120, ct_len + 3); 

        free(plain);
        free(ct);
        free(times);
    }

    eph_free_ctx(&ctx);
}

/* ------------------------------------------------------------------ */
/*  Benchmark 5: File size (static, no time)                          */
/* ------------------------------------------------------------------ */

static void bench_file_sizes(const uint8_t *recip_xy64, const uint8_t *fingerprint)
{
    eph_ctx_t ctx;
    eph_init(&ctx);

    for (int s = 0; s < N_SIZES; s++) 
    {
        size_t   pt_len = FILE_SIZES[s].size;
        uint8_t *plain  = malloc(pt_len);
        
        for (size_t i = 0; i < pt_len; i++) 
        {
            plain[i] = (uint8_t)(i & 0xFF);
        }

        pgp_sizes_t sz = measure_pgp_size(&ctx, recip_xy64, fingerprint, plain, pt_len);

        char name[64];
        snprintf(name, sizeof(name), "BenchmarkFileSize/%s", FILE_SIZES[s].name);

        print_row(name, 0.0, 0.0, 0.0, 1, pt_len, sz.encrypted_bytes, sz.overhead_bytes, sz.header_bytes, sz.payload_bytes);

        free(plain);
    }

    eph_free_ctx(&ctx);
}

/* ------------------------------------------------------------------ */
/*  Benchmark 6: Encrypt Hardware                                     */
/* ------------------------------------------------------------------ */

static void bench_encrypt_hw(int n_runs, int fd, int slot, const uint8_t *fingerprint)
{
    eph_ctx_t ctx;
    eph_init(&ctx);

    for (int s = 0; s < N_SIZES; s++) 
    {
        size_t   pt_len = FILE_SIZES[s].size;
        uint8_t *plain  = malloc(pt_len);
        
        for (size_t i = 0; i < pt_len; i++) 
        {
            plain[i] = (uint8_t)(i & 0xFF);
        }

        double *times   = malloc((size_t)n_runs * sizeof(double));
        double *valid_t = malloc((size_t)n_runs * sizeof(double));
        int     valid   = 0;

        uint8_t last_pub[64] = {0}; 

        for (int i = 0; i < n_runs; i++) 
        {
            double t0 = now_ms();

            uint8_t recip_pub[64] = {0};
            uint8_t slot_b = (uint8_t)slot;
            uint8_t pub_cmd = 0; uint16_t pub_len = 0;
            
            if (device_send_cmd(fd, CMD_GET_PUBLIC_KEY, &slot_b, 1, &pub_cmd, recip_pub, &pub_len) != 0 || pub_len != 64) 
            {
                fprintf(stderr, "  [warn] CMD_GET_PUBLIC_KEY fail iter %d\n", i);
                times[i] = -1.0;
                continue;
            
            }
            memcpy(last_pub, recip_pub, 64);

            uint8_t shared[32], wrapping_key[32], session_key[32], wrapped_sk[40];
            uint8_t eph65[65];
            eph_gen(&ctx, eph65);
            ecdh_soft(&ctx, recip_pub, shared);
            pgp_ecdh_kdf(shared, fingerprint, wrapping_key);
            mbedtls_ctr_drbg_random(&ctx.ctr_drbg, session_key, 32);
            aes256_key_wrap(wrapping_key, session_key, wrapped_sk);

            uint8_t *ct = NULL; size_t ct_len = 0;
            seipd_encrypt(session_key, plain, pt_len, &ct, &ct_len);

            times[i] = now_ms() - t0;

            free(ct);
            memset(shared, 0, 32);
            memset(wrapping_key, 0, 32);
            memset(session_key, 0, 32);
        }

        for (int i = 0; i < n_runs; i++) 
        {
            if (times[i] >= 0) 
            {
                valid_t[valid++] = times[i];
            }
        }

        pgp_sizes_t sz = {0};
        if (valid > 0 && last_pub[0] != 0) 
        {
            sz = measure_pgp_size(&ctx, last_pub, fingerprint, plain, pt_len);
        }

        char name[64];
        snprintf(name, sizeof(name), "BenchmarkEncrypt_Hard/%s", FILE_SIZES[s].name);

        if (valid > 0) 
        {
            double med = median_sorted(valid_t, valid);
            print_row(name, med, valid_t[0], valid_t[valid-1], valid, pt_len, sz.encrypted_bytes, sz.overhead_bytes, sz.header_bytes, sz.payload_bytes);
        } 
        else 
        {
            fprintf(stderr, "[warn] No results Encrypt_Hard/%s\n", FILE_SIZES[s].name);
        }

        free(plain);
        free(times);
        free(valid_t);
    }

    eph_free_ctx(&ctx);
}

/* ------------------------------------------------------------------ */
/*  Benchmark 7: Decrypt Hardware                                     */
/* ------------------------------------------------------------------ */

static void bench_decrypt_hw(int n_runs, int fd, int slot, const uint8_t *recip_pub, const uint8_t *fingerprint)
{
    fprintf(stderr, "[bench_pgp] ECDH Hardware: %d iterations\n"
        "  Press TUP before each iteration, then ENTER.\n\n",
        n_runs);

    eph_ctx_t ctx;
    eph_init(&ctx);

    for (int s = 0; s < N_SIZES; s++) 
    {
        int runs = n_runs;

        size_t   pt_len = FILE_SIZES[s].size;
        uint8_t *plain  = malloc(pt_len);
        
        for (size_t i = 0; i < pt_len; i++) 
        { 
            plain[i] = (uint8_t)(i & 0xFF);
        }

        uint8_t shared_enc[32], wrapping_enc[32], session_key[32], wrapped_sk[40];
        uint8_t eph65[65];
        eph_gen(&ctx, eph65);
        ecdh_soft(&ctx, recip_pub, shared_enc);
        pgp_ecdh_kdf(shared_enc, fingerprint, wrapping_enc);
        mbedtls_ctr_drbg_random(&ctx.ctr_drbg, session_key, 32);
        aes256_key_wrap(wrapping_enc, session_key, wrapped_sk);

        uint8_t *ct = NULL; size_t ct_len = 0;
        seipd_encrypt(session_key, plain, pt_len, &ct, &ct_len);

        uint8_t ecdh_payload[65];
        ecdh_payload[0] = (uint8_t)slot;
        memcpy(ecdh_payload + 1, eph65 + 1, 64);

        double *times = malloc((size_t)runs * sizeof(double));
        double *valid_t = malloc((size_t)runs * sizeof(double));
        int valid = 0;

        fprintf(stderr, "\n  === Decrypt_Hard/%s (%d iterations) ===\n", FILE_SIZES[s].name, runs);

        for (int i = 0; i < runs; i++) 
        {
            uint8_t resp_cmd = 0, resp[32] = {0};
            uint16_t resp_len = 0;
            device_send_cmd(fd, CMD_ECDH_REQUEST, ecdh_payload, 65, &resp_cmd, resp, &resp_len);

            fprintf(stderr, "  [%d/%d] Press TUP, then ENTER: ", i + 1, runs);
            int ch; while ((ch = getchar()) != '\n' && ch != EOF);

            double t0 = now_ms();

            resp_cmd = 0; resp_len = 0;
            device_send_cmd(fd, CMD_ECDH_REQUEST, ecdh_payload, 65, &resp_cmd, resp, &resp_len);

            if (resp_cmd != CMD_ECDH_REQUEST || resp_len != 32) 
            {
                fprintf(stderr, "  FAIL ECDH iter %d/%s (cmd=0x%02X len=%u)\n", i, FILE_SIZES[s].name, resp_cmd, resp_len);
                times[i] = -1.0;
                continue;
            }

            uint8_t shared_hw[32];
            memcpy(shared_hw, resp, 32);

            uint8_t wrapping_hw[32];
            pgp_ecdh_kdf(shared_hw, fingerprint, wrapping_hw);

            uint8_t recovered_sk[32];
            if (aes256_key_unwrap(wrapping_hw, wrapped_sk, recovered_sk) != 0) 
            {
                fprintf(stderr, "  FAIL KeyUnwrap iter %d\n", i);
                times[i] = -1.0;
                memset(shared_hw,   0, 32);
                memset(wrapping_hw, 0, 32);
                continue;
            }

            uint8_t *out = NULL; size_t out_len = 0;
            int rc = seipd_decrypt(recovered_sk, ct, ct_len, &out, &out_len);

            times[i] = now_ms() - t0;

            if (rc != 0) 
            {
                fprintf(stderr, "  FAIL SEIPD decrypt iter %d (rc=%d)\n", i, rc);
                times[i] = -1.0;
            }

            free(out);
            memset(shared_hw, 0, 32);
            memset(wrapping_hw, 0, 32);
            memset(recovered_sk, 0, 32);
        }

        for (int i = 0; i < runs; i++) 
        {
            if (times[i] >= 0) 
            {
                valid_t[valid++] = times[i];
            }
        }

        char name[64];
        snprintf(name, sizeof(name), "BenchmarkDecrypt_Hard/%s", FILE_SIZES[s].name);

        if (valid > 0) 
        {
            double med = median_sorted(valid_t, valid);
            print_row(name, med, valid_t[0], valid_t[valid-1], valid, pt_len, ct_len + 123, 163, 120, ct_len + 3); 
        } 
        else 
        {
            fprintf(stderr, "[warn] No results Decrypt_Hard/%s\n", FILE_SIZES[s].name);
        }

        free(plain);
        free(ct);
        free(times);
        free(valid_t);
    }

    eph_free_ctx(&ctx);
}

/* ------------------------------------------------------------------ */
/*  main                                                              */
/* ------------------------------------------------------------------ */

int main(int argc, char *argv[])
{
    const char *port = "/dev/ttyACM0";
    int slot = 0;
    int n_runs = 20;
    int do_hw = 1;

    for (int i = 1; i < argc; i++) 
    {
        if (!strcmp(argv[i], "--port") && i+1 < argc) port = argv[++i];
        if (!strcmp(argv[i], "--slot") && i+1 < argc) slot = atoi(argv[++i]);
        if (!strcmp(argv[i], "--runs") && i+1 < argc) n_runs = atoi(argv[++i]);
        if (!strcmp(argv[i], "--no-hw")) do_hw = 0;
    }

    printf("benchmark,median_ms,min_ms,max_ms,n_runs,bytes,"
           "encrypted_bytes,overhead_bytes,header_bytes,payload_bytes\n");

    int fd = -1;
    uint8_t recip_pub[64] = {0};

    if (do_hw) 
    {
        fd = device_open(port);
        
        if (fd < 0) 
        {
            fprintf(stderr, "Brak Pico na %s — pomijam benchmarki hardware\n", port);
            do_hw = 0;
        } 
        else 
        {
            uint8_t slot_b = (uint8_t)slot;
            uint8_t pub_cmd = 0; uint16_t pub_len = 0;
            
            if (device_send_cmd(fd, CMD_GET_PUBLIC_KEY, &slot_b, 1, &pub_cmd, recip_pub, &pub_len) != 0 || pub_len != 64) 
            {
                fprintf(stderr, "Error getting pub key\n");
                device_close(fd); do_hw = 0;
            }
        }
    }

    if (!do_hw) 
    {
        eph_ctx_t tmp; eph_init(&tmp);
        uint8_t pub65[65];
        eph_gen(&tmp, pub65);
        memcpy(recip_pub, pub65 + 1, 64);
        eph_free_ctx(&tmp);
    }

    uint8_t fingerprint[20];
    {
        mbedtls_sha1_context sha;
        mbedtls_sha1_init(&sha);
        mbedtls_sha1_starts(&sha);
        mbedtls_sha1_update(&sha, recip_pub, 64);
        mbedtls_sha1_finish(&sha, fingerprint);
        mbedtls_sha1_free(&sha);
    }

    fprintf(stderr, "\n=== [1/7] ECDH Software (%d runs) ===\n", n_runs);
    bench_ecdh_soft(n_runs, recip_pub);

    if (do_hw) 
    {
        fprintf(stderr, "\n=== [2/7] ECDH Hardware (%d runs) ===\n", n_runs);
        bench_ecdh_hw(n_runs, fd, slot);
    }

    fprintf(stderr, "\n=== [3/7] Encrypt Software (%d runs x %d sizes) ===\n", n_runs, N_SIZES);
    bench_encrypt_soft(n_runs, recip_pub, fingerprint);

    if (do_hw) 
    {
        fprintf(stderr, "\n=== [4/7] Encrypt Hardware (%d runs x %d sizes) ===\n"
                        "  Measured time: CMD_GET_PUBLIC_KEY + soft ECDH + encrypt\n\n",
                n_runs, N_SIZES);
        bench_encrypt_hw(n_runs, fd, slot, fingerprint);
    }

    fprintf(stderr, "\n=== [5/7] Decrypt Software (%d runs x %d sizes) ===\n", n_runs, N_SIZES);
    bench_decrypt_soft(n_runs, recip_pub, fingerprint);

    if (do_hw) 
    {
        fprintf(stderr,
            "\n=== [6/7] Decrypt Hardware (%d runs x %d sizes) ===\n"
            "  For each iteration/size: press TUP, then ENTER.\n",
            n_runs, N_SIZES);
        bench_decrypt_hw(n_runs, fd, slot, recip_pub, fingerprint);
    }

    fprintf(stderr, "\n=== [7/7] File Sizes ===\n");
    bench_file_sizes(recip_pub, fingerprint);

    if (do_hw) 
    {
        device_close(fd);
    }

    fprintf(stderr, "\nReady. Results in stdout (CSV).\n");

    return 0;
}