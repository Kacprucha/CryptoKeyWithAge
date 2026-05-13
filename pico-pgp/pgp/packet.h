#ifndef PGP_PACKET_H
#define PGP_PACKET_H

#include <stdint.h>
#include <stddef.h>

#define PKT_TAG_PKESK  1
#define PKT_TAG_SEIPD  18

/*
 * packet_write_pkesk – builds a PKESK packet 
*/
int packet_write_pkesk(const uint8_t *key_id, const uint8_t *eph_pub_xy, const uint8_t *wrapped_sk, uint8_t *out, size_t *out_len);

/*
* packet_write_seipd – builds a SEIPD packet
*/
int packet_write_seipd(const uint8_t *ciphertext, size_t ct_len, uint8_t *out, size_t *out_len);

/*
 * packet_parse_pkesk – parses a PKESK packet from raw .pgp bytes
*/
int packet_parse_pkesk(const uint8_t *data, size_t data_len, uint8_t *eph_pub_xy, uint8_t *wrapped_sk, size_t *consumed);

/*
 * packet_parse_seipd – parses the SEIPD packet, returns a pointer to the ciphertext.
*/
int packet_parse_seipd(const uint8_t *data, size_t data_len, const uint8_t **ciphertext, size_t *ct_len, size_t *consumed);

#endif