#ifndef PKESK_H
#define PKESK_H

#include <stdint.h>
#include <stddef.h>

/* PKESK packet parsing result for ECDH P-256 */
typedef struct {
    uint8_t  key_id[8];
    uint8_t  eph_pub_xy[64];
    uint8_t  encrypted_sk[56];
    size_t   encrypted_sk_len;
} pkesk_t;

int pkesk_parse(const uint8_t *pgp_data, size_t pgp_len, pkesk_t *out);

#endif