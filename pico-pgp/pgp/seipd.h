#ifndef PGP_SEIPD_H
#define PGP_SEIPD_H

#include <stdint.h>
#include <stddef.h>

int seipd_encrypt(const uint8_t *session_key, const uint8_t *plaintext, size_t pt_len, uint8_t **ciphertext, size_t *ct_len);
int seipd_decrypt(const uint8_t *session_key, const uint8_t *ciphertext, size_t ct_len, uint8_t **plaintext, size_t  *pt_len);

#endif