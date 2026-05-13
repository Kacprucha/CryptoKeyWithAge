#include "kdf.h"
#include <mbedtls/sha256.h>
#include <string.h>

static const uint8_t OID_NISTP256[] = 
{
    0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07
};

int pgp_ecdh_kdf(
    const uint8_t *shared_secret, /* 32B – ECDH */
    const uint8_t *fingerprint,   /* 20B – SHA-1 key */
    uint8_t *wrapping_key         /* 32B – KDF result */
) 
{
    mbedtls_sha256_context ctx;
    mbedtls_sha256_init(&ctx);
    mbedtls_sha256_starts(&ctx, 0); /* 0 = SHA-256 */

    /* Counter = 0x00000001 */
    uint8_t counter[4] = {0x00, 0x00, 0x00, 0x01};
    mbedtls_sha256_update(&ctx, counter, 4);

    /* shared_secret */
    mbedtls_sha256_update(&ctx, shared_secret, 32);

    uint8_t param_len = 0x13;
    mbedtls_sha256_update(&ctx, &param_len, 1);
    uint8_t oid_len = sizeof(OID_NISTP256);
    mbedtls_sha256_update(&ctx, &oid_len, 1);
    mbedtls_sha256_update(&ctx, OID_NISTP256, oid_len);

    uint8_t algos[2] = {0x08, 0x09};
    mbedtls_sha256_update(&ctx, algos, 2);

    mbedtls_sha256_update(&ctx, (const uint8_t *)"Anonymous Sender    ", 20);

    mbedtls_sha256_update(&ctx, fingerprint, 20);

    mbedtls_sha256_finish(&ctx, wrapping_key);
    mbedtls_sha256_free(&ctx);
    
    return 0;
}