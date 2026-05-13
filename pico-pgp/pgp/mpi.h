#ifndef PGP_MPI_H
#define PGP_MPI_H

#include <stdint.h>
#include <stddef.h>

/* Encode point EC (64B X||Y) as MPI. 
 * out must be at least 67B. 
 * out_len = 67 on return. 
*/
int mpi_encode_point(const uint8_t *xy64, uint8_t *out, size_t *out_len);

/* Decode MPI containing point EC → 64B X||Y.
 * consumed = number of bytes consumed from MPI (including 2B header).
 * Returns 0 on success, -1 on error (bad format or not uncompressed). 
*/
int mpi_decode_point(const uint8_t *mpi, size_t mpi_len, uint8_t *xy64, size_t *consumed);

#endif