#include "kdf.h"
#include <mbedtls/sha256.h>
#include <string.h>

static const uint8_t OID_NISTP256[] = 
{
    0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07
};

static const uint8_t ANONYMOUS_SENDER[20] = "Anonymous Sender    ";

int pgp_ecdh_kdf(
    const uint8_t *shared_secret, /* 32B – ECDH */
    const uint8_t *fingerprint,   /* 20B – SHA-1 key */
    uint8_t *wrapping_key         /* 32B – KDF result */
) 
{
    mbedtls_sha256_context ctx;
    mbedtls_sha256_init(&ctx);
    mbedtls_sha256_starts(&ctx, 0);

    uint8_t counter[4] = {0x00, 0x00, 0x00, 0x01};
    mbedtls_sha256_update(&ctx, counter, 4);
    mbedtls_sha256_update(&ctx, shared_secret, 32);

    uint8_t oid_len = sizeof(OID_NISTP256);  /* = 8 */
    mbedtls_sha256_update(&ctx, &oid_len, 1);
    mbedtls_sha256_update(&ctx, OID_NISTP256, oid_len);

    uint8_t algo_ecdh = 0x12;
    mbedtls_sha256_update(&ctx, &algo_ecdh, 1);

    uint8_t kdf_params[4] = {0x03, 0x01, 0x08, 0x07};
    mbedtls_sha256_update(&ctx, kdf_params, 4);

    mbedtls_sha256_update(&ctx, ANONYMOUS_SENDER, 20);
    mbedtls_sha256_update(&ctx, fingerprint, 20);

    uint8_t sha256_out[32];
    mbedtls_sha256_finish(&ctx, sha256_out);
    mbedtls_sha256_free(&ctx);

    memcpy(wrapping_key, sha256_out, 16);
    return 0;
}