#include "keywrap.h"
#include <mbedtls/aes.h>
#include <string.h>

static const uint8_t DEFAULT_IV[8] = 
{
    0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6
};

int aes256_key_wrap(
    const uint8_t *kek,      /* 32B Key Encryption Key */
    const uint8_t *plainkey, /* 32B key for encryption */
    uint8_t *wrapped         /* 40B result */
) 
{
    uint8_t A[8];
    uint8_t R[4][8]; 
    memcpy(A, DEFAULT_IV, 8);
    
    for (int i = 0; i < 4; i++) 
    {
        memcpy(R[i], plainkey + i * 8, 8);
    }

    mbedtls_aes_context aes;
    mbedtls_aes_init(&aes);
    mbedtls_aes_setkey_enc(&aes, kek, 256);

    uint8_t block[16];
    for (int j = 0; j < 6; j++) 
    {
        for (int i = 0; i < 4; i++) 
        {
            memcpy(block, A, 8);
            memcpy(block + 8, R[i], 8);
            uint8_t out[16];
            mbedtls_aes_crypt_ecb(&aes, MBEDTLS_AES_ENCRYPT, block, out);
            uint64_t t = (uint64_t)(4 * j + i + 1);
            for (int k = 0; k < 8; k++) 
            {
                A[k] = out[k] ^ ((t >> (56 - 8 * k)) & 0xff);
            }
            
            memcpy(R[i], out + 8, 8);
        }
    }
    mbedtls_aes_free(&aes);

    memcpy(wrapped, A, 8);
    for (int i = 0; i < 4; i++) 
    {
        memcpy(wrapped + 8 + i * 8, R[i], 8);
    }
    
    return 0;
}

int aes256_key_unwrap(
    const uint8_t *kek,     /* 32B Key Encryption Key */
    const uint8_t *wrapped, /* 40B enctypted key */
    uint8_t *plainkey       /* 32B result */
) 
{
    uint8_t A[8];
    uint8_t R[4][8];
    memcpy(A, wrapped, 8);
    
    for (int i = 0; i < 4; i++) 
    {
        memcpy(R[i], wrapped + 8 + i * 8, 8);
    }

    mbedtls_aes_context aes;
    mbedtls_aes_init(&aes);
    mbedtls_aes_setkey_dec(&aes, kek, 256);

    uint8_t block[16];
    for (int j = 5; j >= 0; j--) 
    {
        for (int i = 3; i >= 0; i--) 
        {
            uint64_t t = (uint64_t)(4 * j + i + 1);
            uint8_t Axor[8];
            
            for (int k = 0; k < 8; k++) 
            {
                Axor[k] = A[k] ^ ((t >> (56 - 8 * k)) & 0xff);
            }
            
            memcpy(block, Axor, 8);
            memcpy(block + 8, R[i], 8);
            uint8_t out[16];
            mbedtls_aes_crypt_ecb(&aes, MBEDTLS_AES_DECRYPT, block, out);
            memcpy(A, out, 8);
            memcpy(R[i], out + 8, 8);
        }
    }

    mbedtls_aes_free(&aes);

    if (memcmp(A, DEFAULT_IV, 8) != 0) 
    {
        return -1; 
    }
    
    for (int i = 0; i < 4; i++) 
    {
        memcpy(plainkey + i * 8, R[i], 8);
    }

    return 0;
}