#include "packet.h"
#include "mpi.h"

#include <string.h>
#include <stdlib.h>

static size_t encode_length(size_t length, uint8_t *out)
{
    if (length < 192) 
    {
        out[0] = (uint8_t)length;
        return 1;
    } 
    else if (length < 8384) 
    {
        length -= 192;
        out[0] = (uint8_t)((length >> 8) + 192);
        out[1] = (uint8_t)(length & 0xFF);
        return 2;
    } 
    else 
    {
        out[0] = 0xFF;
        out[1] = (uint8_t)(length >> 24);
        out[2] = (uint8_t)(length >> 16);
        out[3] = (uint8_t)(length >> 8);
        out[4] = (uint8_t)(length & 0xFF);
        return 5;
    }
}

static size_t decode_length(const uint8_t *data, size_t data_len, size_t *length)
{
    if (data_len < 1) 
    {
        return 0;
    }

    if (data[0] < 192) 
    {
        *length = data[0];
        return 1;
    } 
    else if (data[0] < 224) 
    {
        if (data_len < 2) 
        {
            return 0;
        }

        *length = ((size_t)(data[0] - 192) << 8) + data[1] + 192;
        return 2;
    } 
    else if (data[0] == 0xFF) 
    {
        if (data_len < 5) 
        {
            return 0;
        }

        *length = ((size_t)data[1] << 24) | ((size_t)data[2] << 16) | ((size_t)data[3] << 8)  |  (size_t)data[4];
        return 5;
    }

    /* 224–254: partial body length – not supported in this project */
    return 0;
}

static int find_packet(const uint8_t *data, size_t data_len, int want_tag, size_t *payload_offset, size_t *payload_len, size_t *total_consumed)
{
    size_t pos = 0;

    while (pos < data_len) 
    {
        if (data[pos] == 0x00 || !(data[pos] & 0x80)) 
        {
            return -1; /* invalid byte tag */
        }

        int tag;
        size_t header_size;
        size_t plen;

        if (data[pos] & 0x40) 
        {
            /* New format: 11xxxxxx */
            tag = data[pos] & 0x3F;
            pos++;
            size_t len_bytes = decode_length(data + pos, data_len - pos, &plen);
            
            if (len_bytes == 0) 
            {
                return -1;
            }

            header_size = 1 + len_bytes;
            pos += len_bytes;
        } 
        else 
        {
            /* Old format: 10ttttll */
            tag = (data[pos] & 0x3C) >> 2;
            int len_type = data[pos] & 0x03;
            pos++;
            header_size = 1;

            if (len_type == 0) 
            {
                if (pos >= data_len) 
                {
                    return -1;
                }

                plen = data[pos++]; header_size++;
            } 
            else if (len_type == 1) 
            {
                if (pos + 1 >= data_len) 
                {
                    return -1;
                }

                plen = ((size_t)data[pos] << 8) | data[pos+1];
                pos += 2; header_size += 2;
            } 
            else if (len_type == 2) 
            {
                if (pos + 3 >= data_len) 
                {
                    return -1;
                }

                plen = ((size_t)data[pos]   << 24) | ((size_t)data[pos+1] << 16) | ((size_t)data[pos+2] <<  8) |  (size_t)data[pos+3];
                pos += 4; header_size += 4;
            } 
            else 
            {
                return -1; /* indeterminate length – not supported */
            }
        }

        if (tag == want_tag) 
        {
            *payload_offset = pos;
            *payload_len = plen;
            *total_consumed = pos + plen;
            return 0;
        }

        pos += plen;
    }

    return -1; /* not found */
}

int packet_write_pkesk(const uint8_t *key_id, const uint8_t *eph_pub_xy, const uint8_t *wrapped_sk, uint8_t *out, size_t *out_len)
{
    uint8_t payload[128];
    size_t  pos = 0;

    payload[pos++] = 0x03; /* version */
    memcpy(payload + pos, key_id, 8); /* key ID */
    pos += 8;
    payload[pos++] = 0x12; /* ECDH algorithm */

    /* MPI point */
    size_t mpi_len = 0;
    if (mpi_encode_point(eph_pub_xy, payload + pos, &mpi_len) != 0) 
    {
        return -1;
    }
    pos += mpi_len;

    payload[pos++] = 40;
    memcpy(payload + pos, wrapped_sk, 40);
    pos += 40;

    /* Header: tag byte (new format) + length */
    size_t header_pos = 0;
    uint8_t header[6];
    header[header_pos++] = 0xC0 | PKT_TAG_PKESK; 
    size_t len_bytes = encode_length(pos, header + header_pos);
    header_pos += len_bytes;

    memcpy(out, header, header_pos);
    memcpy(out + header_pos, payload, pos);
    *out_len = header_pos + pos;

    return 0;
}

int packet_write_seipd(const uint8_t *ciphertext, size_t ct_len, uint8_t *out, size_t *out_len)
{
    size_t payload_len = 1 + ct_len;

    /* Header */
    uint8_t header[6];
    size_t  hpos = 0;
    header[hpos++] = 0xC0 | PKT_TAG_SEIPD; 
    hpos += encode_length(payload_len, header + hpos);

    memcpy(out, header, hpos);
    out[hpos] = 0x01; /* version */
    memcpy(out + hpos + 1, ciphertext, ct_len);
    *out_len = hpos + payload_len;
    
    return 0;
}

int packet_parse_pkesk(const uint8_t *data, size_t data_len, uint8_t *eph_pub_xy, uint8_t *wrapped_sk, size_t *consumed)
{
    size_t payload_off, payload_len, total;

    if (find_packet(data, data_len, PKT_TAG_PKESK, &payload_off, &payload_len, &total) != 0) 
    {
        return -1;
    }

    const uint8_t *p = data + payload_off;
    size_t pos = 0;

    /* version */
    if (pos >= payload_len || p[pos] != 0x03) 
    { 
        return -1;
    }
    pos++;

    /* key_id: skipping 8B */
    if (pos + 8 > payload_len) 
    { 
        return -1;
    }
    pos += 8;

    /* algo: must be 0x12 = ECDH */
    if (pos >= payload_len || p[pos] != 0x12) 
    { 
        return -1;
    }
    pos++;

    /* MPI → X||Y */
    size_t mpi_consumed = 0;
    if (mpi_decode_point(p + pos, payload_len - pos, eph_pub_xy, &mpi_consumed) != 0) 
    {
        return -1;
    }
    pos += mpi_consumed;

    /* wrapped_sk_len */
    if (pos >= payload_len || p[pos] != 40) 
    { 
        return -1;
    }
    pos++;

    /* wrapped_sk */
    if (pos + 40 > payload_len) 
    {
        return -1;
    }
    memcpy(wrapped_sk, p + pos, 40);

    *consumed = total;

    return 0;
}

int packet_parse_seipd(const uint8_t  *data, size_t data_len, const uint8_t **ciphertext, size_t *ct_len, size_t *consumed)
{
    size_t payload_off, payload_len, total;

    if (find_packet(data, data_len, PKT_TAG_SEIPD, &payload_off, &payload_len, &total) != 0) 
    {
        return -1;
    }

    /* Check if verison = 0x01 */
    if (payload_len < 2 || data[payload_off] != 0x01) 
    {
        return -1;
    }

    *ciphertext = data + payload_off + 1;
    *ct_len = payload_len - 1;
    *consumed = total;
    
    return 0;
}