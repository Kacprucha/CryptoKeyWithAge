#ifndef PGP_KEYWRAP_H
#define PGP_KEYWRAP_H

#include <stdint.h>

int aes256_key_wrap(const uint8_t *kek, const uint8_t *plainkey, uint8_t *wrapped);
int aes256_key_unwrap(const uint8_t *kek, const uint8_t *wrapped, uint8_t *plainkey);

#endif