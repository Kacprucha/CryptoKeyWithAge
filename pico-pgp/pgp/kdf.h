#ifndef PGP_KDF_H
#define PGP_KDF_H

#include <stdint.h>

int pgp_ecdh_kdf(const uint8_t *shared_secret, const uint8_t *fingerprint, uint8_t *wrapping_key);

#endif