#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

static int g_tests_run = 0;
static int g_tests_passed = 0;
static int g_tests_failed = 0;

#define TEST_BEGIN(name) \
    do { \
        g_tests_run++; \
        const char *_test_name = (name); \
        int _test_ok = 1;

#define EXPECT_MEMEQ(label, got, want, len) \
    do { \
        if (memcmp((got), (want), (len)) != 0) { \
            fprintf(stderr, "  FAIL [%s] %s\n    got:  ", _test_name, label); \
            for (int _i = 0; _i < (int)(len); _i++) \
                fprintf(stderr, "%02X", ((const uint8_t *)(got))[_i]); \
            fprintf(stderr, "\n    want: "); \
            for (int _i = 0; _i < (int)(len); _i++) \
                fprintf(stderr, "%02X", ((const uint8_t *)(want))[_i]); \
            fprintf(stderr, "\n"); \
            _test_ok = 0; \
        } \
    } while (0)

#define EXPECT_EQ(label, got, want) \
    do { \
        if ((got) != (want)) { \
            fprintf(stderr, "  FAIL [%s] %s: got=%d want=%d\n", \
                    _test_name, label, (int)(got), (int)(want)); \
            _test_ok = 0; \
        } \
    } while (0)

#define TEST_END() \
    do { \
        if (_test_ok) { \
            printf("  PASS [%s]\n", _test_name); \
            g_tests_passed++; \
        } else { \
            g_tests_failed++; \
        } \
    } while (0); \
    } while (0)

int aes256_key_wrap(const uint8_t *kek, const uint8_t *plainkey, uint8_t *wrapped);
int aes256_key_unwrap(const uint8_t *kek, const uint8_t *wrapped, uint8_t *plainkey);
int pgp_ecdh_kdf(const uint8_t *shared_secret, const uint8_t *fingerprint, uint8_t *wrapping_key);

static void hex_decode(const char *hex, uint8_t *out, size_t len) 
{
    for (size_t i = 0; i < len; i++) 
    {
        unsigned int byte;
        sscanf(hex + 2 * i, "%02X", &byte);
        out[i] = (uint8_t)byte;
    }
}

/* RFC 3394 §4.3 – Test vector, AES-256 KEK wrapping 256-bit key
 *
 * KEK  = 000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F
 * Data = 00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F
 * Wrap = 28C9F404C4B810F4CBCCB35CFB87F8263F5786E2D80ED326CBC7F0E71A99F43BFB988B9B7A02DD21
 */
static void test_keywrap_rfc3394_wrap(void) 
{
    TEST_BEGIN("KeyWrap – RFC 3394 §4.3 wrap") 
    {
        uint8_t kek[32], data[32], wrapped[40];

        hex_decode("000102030405060708090A0B0C0D0E0F" "101112131415161718191A1B1C1D1E1F", kek, 32);
        hex_decode("00112233445566778899AABBCCDDEEFF" "000102030405060708090A0B0C0D0E0F", data, 32);

        const uint8_t expected[40] = 
        {
            0x28,0xC9,0xF4,0x04,0xC4,0xB8,0x10,0xF4,
            0xCB,0xCC,0xB3,0x5C,0xFB,0x87,0xF8,0x26,
            0x3F,0x57,0x86,0xE2,0xD8,0x0E,0xD3,0x26,
            0xCB,0xC7,0xF0,0xE7,0x1A,0x99,0xF4,0x3B,
            0xFB,0x98,0x8B,0x9B,0x7A,0x02,0xDD,0x21
        };

        int rc = aes256_key_wrap(kek, data, wrapped);

        EXPECT_EQ("return code", rc, 0);
        EXPECT_MEMEQ("wrapped output", wrapped, expected, 40);

    } 
    
    TEST_END();
}

static void test_keywrap_rfc3394_unwrap(void) {
    TEST_BEGIN("KeyWrap – RFC 3394 §4.3 unwrap") 
    {
        uint8_t kek[32];
        hex_decode("000102030405060708090A0B0C0D0E0F" "101112131415161718191A1B1C1D1E1F", kek, 32);

        const uint8_t wrapped[40] = 
        {
            0x28,0xC9,0xF4,0x04,0xC4,0xB8,0x10,0xF4,
            0xCB,0xCC,0xB3,0x5C,0xFB,0x87,0xF8,0x26,
            0x3F,0x57,0x86,0xE2,0xD8,0x0E,0xD3,0x26,
            0xCB,0xC7,0xF0,0xE7,0x1A,0x99,0xF4,0x3B,
            0xFB,0x98,0x8B,0x9B,0x7A,0x02,0xDD,0x21
        };

        uint8_t expected[32], plainkey[32];
        hex_decode("00112233445566778899AABBCCDDEEFF" "000102030405060708090A0B0C0D0E0F", expected, 32);

        int rc = aes256_key_unwrap(kek, wrapped, plainkey);

        EXPECT_EQ("return code", rc, 0);
        EXPECT_MEMEQ("unwrapped key", plainkey, expected, 32);

    } 
    
    TEST_END();
}

static void test_keywrap_roundtrip(void) 
{
    TEST_BEGIN("KeyWrap – roundtrip random key") 
    {

        /* no rand() for repeatability */
        uint8_t kek[32], plainkey_in[32], wrapped[40], plainkey_out[32];

        for (int i = 0; i < 32; i++) kek[i] = (uint8_t)(0xAA ^ i);
        for (int i = 0; i < 32; i++) plainkey_in[i] = (uint8_t)(0x55 ^ i);

        int rc1 = aes256_key_wrap(kek, plainkey_in, wrapped);
        int rc2 = aes256_key_unwrap(kek, wrapped, plainkey_out);

        EXPECT_EQ("wrap rc",   rc1, 0);
        EXPECT_EQ("unwrap rc", rc2, 0);
        EXPECT_MEMEQ("roundtrip", plainkey_out, plainkey_in, 32);

    } 
    
    TEST_END();
}

static void test_keywrap_bad_kek(void) 
{
    TEST_BEGIN("KeyWrap – wrong KEK → error integration check") 
    {

        uint8_t kek_good[32], kek_bad[32], plainkey[32], wrapped[40];

        for (int i = 0; i < 32; i++) kek_good[i] = (uint8_t)i;
        for (int i = 0; i < 32; i++) plainkey[i] = (uint8_t)(i + 0x80);

        aes256_key_wrap(kek_good, plainkey, wrapped);

        memcpy(kek_bad, kek_good, 32);
        kek_bad[0] ^= 0xFF; /* one bit difference */

        uint8_t out[32];
        int rc = aes256_key_unwrap(kek_bad, wrapped, out);

        EXPECT_EQ("wrong KEK → rc != 0", (rc != 0), 1);

    } 
    
    TEST_END();
}

static void test_keywrap_corrupted_data(void) 
{
    TEST_BEGIN("KeyWrap – corrupted data → integrity check error") 
    {

        uint8_t kek[32], plainkey[32], wrapped[40];

        for (int i = 0; i < 32; i++) kek[i] = (uint8_t)(0x11 * (i % 8));
        for (int i = 0; i < 32; i++) plainkey[i] = (uint8_t)i;

        aes256_key_wrap(kek, plainkey, wrapped);
        wrapped[20] ^= 0x01;  /* flip one bit in the middle of the data */

        uint8_t out[32];
        int rc = aes256_key_unwrap(kek, wrapped, out);

        EXPECT_EQ("corrupt → rc != 0", (rc != 0), 1);

    } 
    
    TEST_END();
}

static void test_kdf_known_vector(void) 
{
    TEST_BEGIN("KDF – known vector (shared_secret=00..1F, fp=00..13)") 
    {

        uint8_t shared_secret[32], fingerprint[20], result[32];

        for (int i = 0; i < 32; i++) shared_secret[i] = (uint8_t)i;
        for (int i = 0; i < 20; i++) fingerprint[i]   = (uint8_t)i;

        int rc = pgp_ecdh_kdf(shared_secret, fingerprint, result);
        EXPECT_EQ("return code", rc, 0);
        
        /* run Python kdf_known_vector_helper.py script to get the correct expected[] value */
        uint8_t expected[32] = 
        { 
            0x83,0x71,0x39,0xA2,0x6D,0xBB,0x7D,0xEA, 
            0xA9,0x9B,0x7A,0x3D,0xA3,0x2F,0x75,0x4E, 
            0xDE,0xB6,0xCC,0x9D,0x4C,0xC2,0xB9,0x92, 
            0x98,0xDF,0x30,0xF3,0xD1,0x44,0x70,0x63 
        };

        EXPECT_MEMEQ("KDF output", result, expected, 32);
    } 
    
    TEST_END();
}

static void test_kdf_deterministic(void) 
{
    TEST_BEGIN("KDF – deterministic (two calls = identical result)") 
    {

        uint8_t shared[32], fp[20], out1[32], out2[32];

        for (int i = 0; i < 32; i++) shared[i] = (uint8_t)(0xCA ^ i);
        for (int i = 0; i < 20; i++) fp[i]     = (uint8_t)(0xFE ^ i);

        pgp_ecdh_kdf(shared, fp, out1);
        pgp_ecdh_kdf(shared, fp, out2);

        EXPECT_MEMEQ("out1 == out2", out1, out2, 32);

    } 
    
    TEST_END();
}

static void test_kdf_avalanche_shared(void) 
{
    TEST_BEGIN("KDF – avalanche: 1-bit flip in shared_secret") 
    {

        uint8_t shared[32], fp[20], out_orig[32], out_flip[32];

        for (int i = 0; i < 32; i++) shared[i] = (uint8_t)i;
        for (int i = 0; i < 20; i++) fp[i]     = 0xAB;

        pgp_ecdh_kdf(shared, fp, out_orig);

        shared[0] ^= 0x01;  /* flip LSB of the first bite */
        pgp_ecdh_kdf(shared, fp, out_flip);

        EXPECT_EQ("results diffrent after flipping", (memcmp(out_orig, out_flip, 32) != 0), 1);

    } 
    
    TEST_END();
}

static void test_kdf_avalanche_fingerprint(void) 
{
    TEST_BEGIN("KDF – avalanche: 1-bit flip in fingerprint") 
    {

        uint8_t shared[32], fp[20], out_orig[32], out_flip[32];

        for (int i = 0; i < 32; i++) shared[i] = 0x42;
        for (int i = 0; i < 20; i++) fp[i]     = (uint8_t)i;

        pgp_ecdh_kdf(shared, fp, out_orig);

        fp[10] ^= 0x80;  /* flip MSB of the middle bite */
        pgp_ecdh_kdf(shared, fp, out_flip);

        EXPECT_EQ("fingerprint affects the result", (memcmp(out_orig, out_flip, 32) != 0), 1);

    } 
    
    TEST_END();
}

static void test_integration_kdf_keywrap(void) {
    TEST_BEGIN("Integration: KDF → KeyWrap → KeyUnwrap → identical session key") {

        /* Simulation: sender side */
        uint8_t shared_secret[32], fingerprint[20];
        uint8_t session_key[32];   /* symmetric key for data protection */
        uint8_t wrapping_key[32];  /* KDF result */
        uint8_t wrapped[40];       /* session key after AES Key Wrap */

        for (int i = 0; i < 32; i++) shared_secret[i] = (uint8_t)(0x11 * (i % 15));
        for (int i = 0; i < 20; i++) fingerprint[i] = (uint8_t)(0x22 * (i % 7));
        for (int i = 0; i < 32; i++) session_key[i] = (uint8_t)(0xAA ^ (i * 3));

        /* 1. KDF: shared_secret + fingerprint → wrapping_key */
        int rc = pgp_ecdh_kdf(shared_secret, fingerprint, wrapping_key);
        EXPECT_EQ("kdf rc", rc, 0);

        /* 2. KeyWrap: wrapping_key + session_key → wrapped */
        rc = aes256_key_wrap(wrapping_key, session_key, wrapped);
        EXPECT_EQ("wrap rc", rc, 0);

        /* Simulation: recipient side (same shared_secret from ECDH) */
        uint8_t wrapping_key2[32], recovered_sk[32];

        /* 3. KDF on the recipient side (identical inputs) */
        rc = pgp_ecdh_kdf(shared_secret, fingerprint, wrapping_key2);
        EXPECT_EQ("kdf2 rc", rc, 0);
        EXPECT_MEMEQ("identical wrapping_key", wrapping_key2, wrapping_key, 32);

        /* 4. KeyUnwrap: recover session key */
        rc = aes256_key_unwrap(wrapping_key2, wrapped, recovered_sk);
        EXPECT_EQ("unwrap rc", rc, 0);
        EXPECT_MEMEQ("session key recovered", recovered_sk, session_key, 32);

    } TEST_END();
}

int main(void) {
    printf("=== Unit tests: KDF + KeyWrap (pico-pgp) ===\n\n");

    printf("--- AES-256 Key Wrap (RFC 3394) ---\n");
    test_keywrap_rfc3394_wrap();
    test_keywrap_rfc3394_unwrap();
    test_keywrap_roundtrip();
    test_keywrap_bad_kek();
    test_keywrap_corrupted_data();

    printf("\n--- OpenPGP ECDH KDF (RFC 4880 §13.5) ---\n");
    test_kdf_known_vector();
    test_kdf_deterministic();
    test_kdf_avalanche_shared();
    test_kdf_avalanche_fingerprint();

    printf("\n--- Integration test ---\n");
    test_integration_kdf_keywrap();

    printf("\n=== Result: %d/%d test passed", g_tests_passed, g_tests_run);
    if (g_tests_failed > 0)
        printf(", %d FAILED ===\n", g_tests_failed);
    else
        printf(" ✓ ===\n");

    return g_tests_failed > 0 ? 1 : 0;
}