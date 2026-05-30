#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <stdint.h>

#include <mbedtls/ecp.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/nist_kw.h>
#include <mbedtls/sha1.h>
#include <mbedtls/bignum.h>

#include "timing.h"
#include "../cmd/decrypt.h" 
#include "../cmd/encrypt.h" 
#include "../pgp/kdf.h"
#include "../device/device.h"
#include "../device/protocol.h"

#define N_WARMUP 3
#define N_RUNS_DEF 20

static const int N_SIZES = 6;

static const struct { const char *name; size_t size; } FILE_SIZES[] = 
{
    { "100B", 100 },
    { "1KB", 1024 },
    { "64KB", 64 * 1024 },
    { "1MB", 1024 * 1024 },
    { "10MB", 10 * 1024 * 1024 },
    { "100MB", 100 * 1024 * 1024 },
};

/* ------------------------------------------------------------------ */
/* Narzędzia                                                           */
/* ------------------------------------------------------------------ */
 
static int cmp_double(const void *a, const void *b) 
{
    double da = *(const double *)a, db = *(const double *)b;
    return (da > db) - (da < db);
}
 
static double calc_median(double *arr, int n) 
{
    qsort(arr, (size_t)n, sizeof(double), cmp_double);
    return (n % 2) ? arr[n/2] : (arr[n/2-1] + arr[n/2]) / 2.0;
}
 
static void csv_row(const char *name, double med, double mn, double mx, int n, size_t bytes, size_t enc_bytes, size_t overhead_bytes, size_t header_bytes, size_t payload_bytes)
{
    printf("%s,%.4f,%.4f,%.4f,%d,%zu,%zu,%zu,%zu,%zu\n", name, med, mn, mx, n, bytes, enc_bytes, overhead_bytes, header_bytes, payload_bytes);
}
 
static int gen_test_file(const char *path, size_t size) 
{
    FILE *f = fopen(path, "wb");
    if (!f) 
    {
        return -1;
    }

    uint8_t buf[4096];
    
    for (size_t i = 0; i < sizeof(buf); i++)  
    {
        buf[i] = (uint8_t)(i & 0xFF);
    }

    size_t done = 0;
    
    while (done < size) 
    {
        size_t chunk = size - done;
        if (chunk > sizeof(buf)) chunk = sizeof(buf);
        fwrite(buf, 1, chunk, f);
        done += chunk;
    }

    fclose(f); 
    
    return 0;
}
 
/* ------------------------------------------------------------------ */
/* Kontekst mbedTLS ECDH                                              */
/* ------------------------------------------------------------------ */
 
typedef struct {
    mbedtls_ecp_group grp;
    mbedtls_mpi d;
    mbedtls_ecp_point Q;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context rng;
} ecdh_ctx_t;
 
static void ecdh_ctx_init(ecdh_ctx_t *c) 
{
    mbedtls_ecp_group_init(&c->grp);
    mbedtls_mpi_init(&c->d);
    mbedtls_ecp_point_init(&c->Q);
    mbedtls_entropy_init(&c->entropy);
    mbedtls_ctr_drbg_init(&c->rng);
    mbedtls_ctr_drbg_seed(&c->rng, mbedtls_entropy_func, &c->entropy, (const uint8_t *)"bench", 5);
    mbedtls_ecp_group_load(&c->grp, MBEDTLS_ECP_DP_SECP256R1);
}
 
static void ecdh_ctx_free(ecdh_ctx_t *c) 
{
    mbedtls_ecp_group_free(&c->grp);
    mbedtls_mpi_free(&c->d);
    mbedtls_ecp_point_free(&c->Q);
    mbedtls_ctr_drbg_free(&c->rng);
    mbedtls_entropy_free(&c->entropy);
}
 
static int soft_ecdh(ecdh_ctx_t *c, const uint8_t *recip_xy64, uint8_t *shared32) 
{
    mbedtls_ecp_gen_privkey(&c->grp, &c->d, mbedtls_ctr_drbg_random, &c->rng);
    mbedtls_ecp_mul(&c->grp, &c->Q, &c->d, &c->grp.G, mbedtls_ctr_drbg_random, &c->rng);
 
    uint8_t pub65[65]; pub65[0] = 0x04;
    memcpy(pub65 + 1, recip_xy64, 64);
 
    mbedtls_ecp_point R, S;
    mbedtls_ecp_point_init(&R); mbedtls_ecp_point_init(&S);
    
    int rc = mbedtls_ecp_point_read_binary(&c->grp, &R, pub65, 65);
    if (!rc) 
    {
        rc = mbedtls_ecp_mul(&c->grp, &S, &c->d, &R, mbedtls_ctr_drbg_random, &c->rng);
    }

    if (!rc) 
    {
        uint8_t out[65]; size_t olen = 0;
        rc = mbedtls_ecp_point_write_binary(&c->grp, &S, MBEDTLS_ECP_PF_UNCOMPRESSED, &olen, out, 65);
        
        if (!rc)  
        {
            memcpy(shared32, out + 1, 32);
        }
    }
    
    mbedtls_ecp_point_free(&R); 
    mbedtls_ecp_point_free(&S);
    
    return rc;
}

/* ------------------------------------------------------------------ */
/* Benchmark 1: ECDH Software                                         */
/* ------------------------------------------------------------------ */

static void bench_ecdh_soft(int n, const uint8_t *recip_xy64) 
{
    fprintf(stderr, "[1/5] ECDH Software (%d runs)...\n", n);
    ecdh_ctx_t ctx; ecdh_ctx_init(&ctx);
 
    double *t = malloc((size_t)(n + N_WARMUP) * sizeof(double));
    uint8_t shared[32];
    
    for (int i = 0; i < n + N_WARMUP; i++) 
    {
        double t0 = now_ms();
        soft_ecdh(&ctx, recip_xy64, shared);
        t[i] = now_ms() - t0;
    }
    
    double *v = t + N_WARMUP;
    csv_row("BenchmarkECDH_Software", calc_median(v, n), v[0], v[n-1], n, 0, 0, 0, 0, 0);
    
    free(t); 
    ecdh_ctx_free(&ctx);
}

/* ------------------------------------------------------------------ */
/* Benchmark 2:  ECDH Hardware (bypass TUP)                           */
/* ------------------------------------------------------------------ */

static void bench_ecdh_hw(int n, int fd, int slot) 
{
    fprintf(stderr, "[2/5] ECDH Hardware bypass TUP (%d runs)...\n", n);
 
    ecdh_ctx_t ctx; ecdh_ctx_init(&ctx);
    mbedtls_ecp_gen_privkey(&ctx.grp, &ctx.d, mbedtls_ctr_drbg_random, &ctx.rng);
    mbedtls_ecp_mul(&ctx.grp, &ctx.Q, &ctx.d, &ctx.grp.G, mbedtls_ctr_drbg_random, &ctx.rng);
    
    uint8_t eph65[65]; size_t olen = 0;
    mbedtls_ecp_point_write_binary(&ctx.grp, &ctx.Q, MBEDTLS_ECP_PF_UNCOMPRESSED, &olen, eph65, 65);
    ecdh_ctx_free(&ctx);
 
    uint8_t payload[65]; payload[0] = (uint8_t)slot;
    memcpy(payload + 1, eph65 + 1, 64);
 
    double *vt = malloc((size_t)n * sizeof(double));
    int valid = 0;
 
    for (int i = 0; i < n + N_WARMUP; i++) 
    {
        uint8_t resp[32]; uint16_t resp_len = 0;
        
        double t0 = now_ms();
        int rc = device_send_cmd(fd, CMD_ECDH_REQUEST_BYPASS_TUP, payload, 65, NULL, resp, &resp_len);
        double elapsed = now_ms() - t0;
        
        if (rc != 0 || resp_len != 32) 
        {
            fprintf(stderr, "\tFAIL iter %d\n", i); continue;
        }

        if (i >= N_WARMUP) 
        { 
            vt[valid++] = elapsed;
        }
    }
 
    if (valid > 0) 
    {
        csv_row("BenchmarkECDH_Hardware", calc_median(vt, valid), vt[0], vt[valid-1], valid, 0, 0, 0, 0, 0);
    }

    free(vt);
}

/* ------------------------------------------------------------------ */
/* Benchmark 3: Hardware Encryption (bypass TUP)                      */
/* ------------------------------------------------------------------ */

static void bench_encrypt_hw(int n) 
{
    fprintf(stderr, "[3/5] Encrypt Hardware bypass TUP (%d runs x %d sizes)...\n", n, N_SIZES);

    if (system("gpg --list-keys pico@device > /dev/null 2>&1") != 0) 
    {
        fprintf(stderr, "\t[skip] Key pico@device not in the keychain.\n\tRun: python3 gen_cert.py && gpg --import pico_cert.pgp\n");
        return;
    }
    
    mkdir("/tmp/pico_bench", 0755);

    for (int si = 0; si < N_SIZES; si++) 
    {
        size_t sz = FILE_SIZES[si].size;
        char in[128], out[136];
        
        snprintf(in, sizeof(in), "/tmp/pico_bench/%s.bin", FILE_SIZES[si].name);
        snprintf(out, sizeof(out), "%s.pgp", in);
        gen_test_file(in, sz);

        double *vt = malloc((size_t)n * sizeof(double));
        size_t enc_bytes = 0;
        int valid = 0;

        for (int i = 0; i < n + N_WARMUP; i++) 
        {
            remove(out);
            
            char *args[] = { (char*)in, "--logger", "false" };
            double elapsed = 0.0;
            size_t this_enc = 0;
            int rc = cmd_encrypt(3, args, &elapsed, &this_enc);
            
            if (rc != 0) 
            { 
                fprintf(stderr, "\tFAIL %s iter %d\n", FILE_SIZES[si].name, i); 
                continue; 
            }
            
            if (i >= N_WARMUP) 
            {
                vt[valid++] = elapsed;
                enc_bytes = this_enc;
            }
        }

        if (valid > 0) 
        {
            char name[64];
            snprintf(name, sizeof(name), "BenchmarkEncrypt_Hardware/%s", FILE_SIZES[si].name);

            size_t overhead = (enc_bytes > sz) ? enc_bytes - sz : 0;
            double med = calc_median(vt, valid);

            csv_row(name, med, vt[0], vt[valid-1], valid, sz, enc_bytes, overhead, 0, 0);
        }
        
        free(vt);
    }
}

/* ------------------------------------------------------------------ */
/* Benchmark 4: Hardware Decryption                                   */
/* ------------------------------------------------------------------ */

static void bench_decrypt_hw(int n, int slot, char *port, char *fp_path) 
{
    fprintf(stderr, "[4/5] Decrypt HW (%d runs x %d sizes)...\n", n, N_SIZES);
    
    mkdir("/tmp/pico_bench", 0755);

    for (int si = 0; si < N_SIZES; si++) 
    {
        size_t sz = FILE_SIZES[si].size;
        char in[128], pgp[136], dec_out[140];
        
        snprintf(in, sizeof(in), "/tmp/pico_bench/%s.bin", FILE_SIZES[si].name);
        snprintf(pgp, sizeof(pgp), "%s.pgp", in);
        snprintf(dec_out, sizeof(dec_out), "%s.dec", in);

        gen_test_file(in, sz);
        char enc_cmd[512];
        snprintf(enc_cmd, sizeof(enc_cmd),
            "gpg --trust-model always --encrypt -r pico@device "
            "--output \"%s\" --batch --yes \"%s\" 2>/dev/null",
            pgp, in);
        
        if (system(enc_cmd) != 0) 
        {
            fprintf(stderr, " \t[skip] GPG encrypt failed: %s\n", FILE_SIZES[si].name);
            continue;
        }

        double *vt = malloc((size_t)n * sizeof(double));
        int valid = 0;

        for (int i = 0; i < n + N_WARMUP; i++) 
        {
            remove(dec_out);

            double elapsed = 0.0;
            char *args[] = { pgp, "--port", port, "--slot", NULL, "--skipp-tup", "true", "--fp", fp_path, "--logger", "false" };
            asprintf(&args[4], "%d", slot);
            
            int rc = cmd_decrypt(11, args, &elapsed);

            if (rc != 0) 
            {
                fprintf(stderr, "\tFAIL decrypt iter %d/%s\n", i, FILE_SIZES[si].name);
                continue;
            }

            if (i >= N_WARMUP) 
            {
                vt[valid++] = elapsed;
            }
        }

        if (valid > 0) 
        {
            char name[64];
            snprintf(name, sizeof(name), "BenchmarkDecrypt_HW/%s", FILE_SIZES[si].name);
            
            double med = calc_median(vt, valid);
            csv_row(name, med, vt[0], vt[valid-1], valid, sz, 0, 0, 0, 0);
        }

        free(vt);
    }
}

/* ------------------------------------------------------------------ */
/*  Benchmark 5: File size (static, no time)                          */
/* ------------------------------------------------------------------ */

static void bench_file_sizes(void) 
{
    fprintf(stderr, "[5/5] File sizes (static, no timing)...\n");
 
    if (system("gpg --list-keys pico@device > /dev/null 2>&1") != 0) 
    {
        fprintf(stderr, "\t[skip] Klucz pico@device nie jest w keyring.\n");
        return;
    }
    
    mkdir("/tmp/pico_bench", 0755);
 
    printf("# FileSize columns: benchmark,plaintext_B,pgp_B,overhead_B\n");
 
    for (int si = 0; si < N_SIZES; si++) 
    {
        size_t sz = FILE_SIZES[si].size;
        char in[128], pgp[136];
        snprintf(in, sizeof(in), "/tmp/pico_bench/sz_%s.bin", FILE_SIZES[si].name);
        snprintf(pgp, sizeof(pgp), "%s.pgp", in);
 
        gen_test_file(in, sz);
 
        char cmd[512];
        snprintf(cmd, sizeof(cmd),
            "gpg --trust-model always --encrypt -r pico@device "
            "--output \"%s\" --batch --yes \"%s\" 2>/dev/null",
            pgp, in);
 
        if (system(cmd) != 0) 
        {
            fprintf(stderr, "\tFAIL encrypt %s\n", FILE_SIZES[si].name);
            continue;
        }
 
        FILE *f = fopen(pgp, "rb");
        size_t pgp_size = 0;
        if (f) 
        {
            fseek(f, 0, SEEK_END);
            pgp_size = (size_t)ftell(f);
            fclose(f);
        }
 
        printf("BenchmarkFileSize/%s,%zu,%zu,%zu\n", FILE_SIZES[si].name, sz, pgp_size, pgp_size > sz ? pgp_size - sz : 0);
    }
}

/* ------------------------------------------------------------------ */
/*  main                                                              */
/* ------------------------------------------------------------------ */

int main(int argc, char *argv[]) 
{
    char *port = "/dev/ttyACM0";
    char *fp_path = "pico_cert.pgp.fp";
    const char *out_csv = NULL;
    int slot = 0, n_runs = N_RUNS_DEF;

    for (int i = 1; i < argc; i++) 
    {
        if (!strcmp(argv[i], "--port") && i+1 < argc) 
        {
            port = argv[++i];
        }
        else if (!strcmp(argv[i], "--slot") && i+1 < argc) 
        {
            slot = atoi(argv[++i]);
        }
        else if (!strcmp(argv[i], "--runs") && i+1 < argc) 
        {
            n_runs = atoi(argv[++i]);
        }
        else if (!strcmp(argv[i], "--fp")   && i+1 < argc) 
        {
            fp_path = argv[++i];
        }
        else if (!strcmp(argv[i], "--out")  && i+1 < argc) 
        {
            out_csv = argv[++i];
        }
    }

    uint8_t fp[20] = {0};
    FILE *f = fopen(fp_path, "rb");
    if (!f) 
    {
        fprintf(stderr, "Error: fingerprint not found %s\nRun: python3 gen_cert.py\n", fp_path);
        return 1;
    }
    
    if (fread(fp, 1, 20, f) != 20) 
    {
        fprintf(stderr, "Error: .fp file must be 20B\n");
        fclose(f); return 1;
    }
    
    fclose(f);
    
    fprintf(stderr, "[*] Fingerprint: ");
    for (int i = 0; i < 20; i++) 
    { 
        fprintf(stderr, "%02x", fp[i]);
    }
    fprintf(stderr, "\n");

    int fd = device_open(port);
    if (fd < 0) 
    {
        fprintf(stderr, "Error: cannot connect to Pico on %s\n", port);
        return 1;
    }
    
    uint8_t recip_pub[64] = {0}; uint16_t pub_len = 0;
    uint8_t slot_b = (uint8_t)slot;
    
    if (device_send_cmd(fd, CMD_GET_PUBLIC_KEY, &slot_b, 1, NULL, recip_pub, &pub_len) != 0 || pub_len != 64) 
    {
        fprintf(stderr, "Error getting public key\n");
        device_close(fd); return 1;
    }

    fprintf(stderr, "[*] Public key from slot %d retrieved\n", slot);

    if (out_csv) 
    {
        fprintf(stderr, "[*] Results → %s\n", out_csv);
    }
    printf("benchmark,median_ms,min_ms,max_ms,n_runs,bytes,encrypted_bytes,overhead_bytes,header_bytes,payload_bytes\n");
    fprintf(stderr,
        "\n=== Benchmarki pico-pgp ===\n"
        "\tPort: %s  Slot: %d  Runs: %d (+%d warmup)\n\n",
        port, slot, n_runs, N_WARMUP);

    bench_ecdh_soft(n_runs, recip_pub);
    bench_ecdh_hw(n_runs, fd, slot);
    bench_encrypt_hw(n_runs);
    bench_decrypt_hw(n_runs, slot, port, fp_path);
    bench_file_sizes();

    device_close(fd);
    fprintf(stderr, "\n[+] Benchmarks finished.\n");
    
    if (out_csv) 
    {
        fprintf(stderr, "\tCSV file: %s\n", out_csv);
    }
    
    return 0;
}