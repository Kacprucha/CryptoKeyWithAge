#include "mpi.h"
#include <string.h>

int mpi_encode_point(const uint8_t *xy64, uint8_t *out, size_t *out_len)
{
    uint8_t full[65];
    full[0] = 0x04;
    memcpy(full + 1, xy64, 64);

    /* Calculate bit_count for a 65-byte string starting at 0x04 */
    uint16_t bit_count = 515; /* hardcoded for P-256 uncompressed*/

    out[0] = (uint8_t)(bit_count >> 8);   /* 0x02 */
    out[1] = (uint8_t)(bit_count & 0xFF); /* 0x03 */
    memcpy(out + 2, full, 65);

    *out_len = 67;
    
    return 0;
}

int mpi_decode_point(const uint8_t *mpi, size_t mpi_len, uint8_t *xy64, size_t *consumed)
{
    if (mpi_len < 4) 
    {
        return -1;
    }

    uint16_t bit_count = ((uint16_t)mpi[0] << 8) | mpi[1];

    size_t data_len = (bit_count + 7) / 8;

    if (2 + data_len > mpi_len) 
    {
        return -1; /* not enough data */
    }

    const uint8_t *data = mpi + 2;

    if (data_len != 65 || data[0] != 0x04) 
    {
        return -1; /* unsupported format */
    }

    memcpy(xy64, data + 1, 64); /* X[32] || Y[32] */
    *consumed = 2 + data_len;   /* 2B header + 65B data */

    return 0;
}