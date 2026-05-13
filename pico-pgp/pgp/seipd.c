#include "seipd.h"

#include <mbedtls/aes.h>
#include <mbedtls/sha1.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>

#include <stdlib.h>
#include <string.h>

static const uint8_t MDC_TRAILER[2] = { 0xD3, 0x14 };

static int aes256_cfb_crypt(const uint8_t *key, int encrypt, const uint8_t *input, size_t len, uint8_t *output)
{
    mbedtls_aes_context aes;
    mbedtls_aes_init(&aes);

    int rc;
    if (encrypt == MBEDTLS_AES_ENCRYPT) 
    {
        rc = mbedtls_aes_setkey_enc(&aes, key, 256);
    }
    else 
    {
        rc = mbedtls_aes_setkey_enc(&aes, key, 256);
    }

    if (rc != 0) 
    {
        mbedtls_aes_free(&aes);
        return -1;
    }

    uint8_t iv[16] = {0};
    size_t  iv_off = 0;

    rc = mbedtls_aes_crypt_cfb128(&aes, encrypt, len, &iv_off, iv, input, output);
    mbedtls_aes_free(&aes);

    return (rc == 0) ? 0 : -1;
}

int seipd_encrypt(const uint8_t *session_key, const uint8_t *plaintext, size_t pt_len, uint8_t **ciphertext, size_t *ct_len)
{
    size_t plain_buf_len = 18 + pt_len + 22;
    uint8_t *plain_buf = malloc(plain_buf_len);
    
    if (!plain_buf) 
    {
        return -1;
    }

    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;

    mbedtls_entropy_init(&entropy);

    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (const uint8_t *)"seipd", 5);
    mbedtls_ctr_drbg_random(&ctr_drbg, plain_buf, 16);
    mbedtls_ctr_drbg_free(&ctr_drbg);

    mbedtls_entropy_free(&entropy);

    plain_buf[16] = plain_buf[14];
    plain_buf[17] = plain_buf[15];

    memcpy(plain_buf + 18, plaintext, pt_len);

    plain_buf[18 + pt_len + 0] = 0xD3;
    plain_buf[18 + pt_len + 1] = 0x14;

    mbedtls_sha1_context sha1;

    mbedtls_sha1_init(&sha1);

    mbedtls_sha1_starts(&sha1);
    mbedtls_sha1_update(&sha1, plain_buf, 18); /* prefix */
    mbedtls_sha1_update(&sha1, plaintext, pt_len); /* plaintext */
    mbedtls_sha1_update(&sha1, MDC_TRAILER, 2); /* 0xD3 0x14 */
    mbedtls_sha1_finish(&sha1, plain_buf + 18 + pt_len + 2); /* 20B SHA-1 */
    
    mbedtls_sha1_free(&sha1);

    uint8_t *ct = malloc(plain_buf_len);
    
    if (!ct) 
    {
        free(plain_buf);
        return -1;
    }

    if (aes256_cfb_crypt(session_key, MBEDTLS_AES_ENCRYPT, plain_buf, plain_buf_len, ct) != 0) 
    {
        free(plain_buf);
        free(ct);

        return -1;
    }

    free(plain_buf);
    *ciphertext = ct;
    *ct_len = plain_buf_len;

    return 0;
}

int seipd_decrypt(const uint8_t *session_key, const uint8_t *ciphertext, size_t ct_len, uint8_t **plaintext, size_t *pt_len)
{
    if (ct_len < 40) 
    {
        return -1;
    }

    uint8_t *plain = malloc(ct_len);
    if (!plain) 
    {
        return -1;
    }

    if (aes256_cfb_crypt(session_key, MBEDTLS_AES_DECRYPT, ciphertext, ct_len, plain) != 0) 
    {
        free(plain);
        return -1;
    }

    if (plain[16] != plain[14] || plain[17] != plain[15]) 
    {
        free(plain);
        return -2; /* invalid session key or corrupted data */
    }

    size_t mdc_pos = ct_len - 22;
    if (plain[mdc_pos] != 0xD3 || plain[mdc_pos + 1] != 0x14) 
    {
        free(plain);
        return -3;
    }

    size_t inner_pt_len = ct_len - 40; /* 18 prefix + 22 MDC */

    mbedtls_sha1_context sha1;
    uint8_t computed_hash[20];

    mbedtls_sha1_init(&sha1);

    mbedtls_sha1_starts(&sha1);
    mbedtls_sha1_update(&sha1, plain, 18); /* prefix */
    mbedtls_sha1_update(&sha1, plain + 18, inner_pt_len); /* plaintext */
    mbedtls_sha1_update(&sha1, MDC_TRAILER, 2); /* 0xD3 0x14 */
    mbedtls_sha1_finish(&sha1, computed_hash);

    mbedtls_sha1_free(&sha1);

    const uint8_t *stored_hash = plain + mdc_pos + 2;
    if (memcmp(computed_hash, stored_hash, 20) != 0) 
    {
        free(plain);
        return -3; /* integrity violation */
    }

    uint8_t *pt = malloc(inner_pt_len > 0 ? inner_pt_len : 1);
    if (!pt) 
    {
        free(plain);
        return -1;
    }

    memcpy(pt, plain + 18, inner_pt_len);
    free(plain);

    *plaintext = pt;
    *pt_len = inner_pt_len;
    
    return 0;
}