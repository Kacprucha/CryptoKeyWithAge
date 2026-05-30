#include <stdio.h>
#include <string.h>
#include "pkesk.h"

static size_t read_new_pkt_len(const uint8_t *p, size_t avail, size_t *consumed)
{
    if (avail < 1) 
    { 
        *consumed = 0; 
        return 0; 
    }

    if (p[0] < 192) 
    {
        *consumed = 1;
        return p[0];
    } 
    else if (p[0] < 224) 
    {
        if (avail < 2) 
        { 
            *consumed = 0; 
            return 0; 
        }

        *consumed = 2;
        
        return ((size_t)(p[0] - 192) << 8) + p[1] + 192;
    } 
    else if (p[0] == 255) 
    {
        if (avail < 5) 
        { 
            *consumed = 0; 
            return 0; 
        }
        
        *consumed = 5;
        
        return ((size_t)p[1] << 24) | ((size_t)p[2] << 16) | ((size_t)p[3] <<  8) | p[4];
    } 
    else 
    {
        fprintf(stderr, "pkesk_parse: partial body header not supported\n");
        *consumed = 0;
        return 0;
    }
}

static int read_mpi(const uint8_t *p, size_t avail, const uint8_t **data_out, size_t *byte_len_out, size_t *total_consumed)
{
    if (avail < 2) 
    {
        fprintf(stderr, "read_mpi: too little data for bit_count\n");
        return -1;
    }

    uint16_t bits = ((uint16_t)p[0] << 8) | p[1];
    size_t   bytes = (bits + 7) / 8;

    if (avail < 2 + bytes) 
    {
        fprintf(stderr, "read_mpi: too little data: need %zu, have %zu\n", 2 + bytes, avail);
        return -1;
    }

    *data_out = p + 2;
    *byte_len_out = bytes;
    *total_consumed = 2 + bytes;
    
    return 0;
}

static int parse_pkesk_body(const uint8_t *body, size_t body_len, pkesk_t *out)
{
    if (body_len < 10) 
    {
        fprintf(stderr, "parse_pkesk_body: body too short (%zu B)\n", body_len);
        return -1;
    }

    uint8_t version = body[0];
    if (version != 3) 
    {
        fprintf(stderr, "parse_pkesk_body: body too short (%zu B)\n", body_len);
        return -1;
    }

    memcpy(out->key_id, body + 1, 8);

    uint8_t algo = body[9];
    if (algo != 18) 
    {
        fprintf(stderr, "parse_pkesk_body: unsupported algo %d (expected 18=ECDH)\n", algo);
        return -1;
    }

    size_t offset = 10;

    const uint8_t *mpi0_data;
    size_t mpi0_len, mpi0_consumed;
    if (read_mpi(body + offset, body_len - offset, &mpi0_data, &mpi0_len, &mpi0_consumed) != 0) 
    {
        return -1;
    }

    if (mpi0_len != 65 || mpi0_data[0] != 0x04) 
    {
        fprintf(stderr, "parse_pkesk_body: unexpected EC point: len=%zu prefix=0x%02x\n\t(expected 65B with prefix 0x04)\n", mpi0_len, mpi0_len > 0 ? mpi0_data[0] : 0);
        return -1;
    }

    memcpy(out->eph_pub_xy, mpi0_data + 1, 32);  /* X */
    memcpy(out->eph_pub_xy + 32, mpi0_data + 33, 32);  /* Y */
    offset += mpi0_consumed;

    if (offset >= body_len) 
    {
        fprintf(stderr, "parse_pkesk_body: no space for encrypted_sk\n");
        return -1;
    }

    size_t esk_len = body[offset++];

    if (offset + esk_len > body_len) 
    {
        fprintf(stderr, "parse_pkesk_body: encrypted_ goes beyond body\n");
        return -1;
    }

    if (esk_len > sizeof(out->encrypted_sk)) 
    {
        fprintf(stderr, "parse_pkesk_body: encrypted_sk too large: %zu\n", esk_len);
        return -1;
    }
    
    memcpy(out->encrypted_sk, body + offset, esk_len);
    out->encrypted_sk_len = esk_len;

    return 0;
}

int pkesk_parse(const uint8_t *pgp_data, size_t pgp_len, pkesk_t *out)
{
    const uint8_t *p = pgp_data;
    const uint8_t *end = pgp_data + pgp_len;

    while (p < end) 
    {
        if (!(*p & 0x80)) 
        {
            fprintf(stderr, "pkesk_parse: invalid tag byte 0x%02x at offset %zu\n", *p, (size_t)(p - pgp_data));
            return -1;
        }

        int new_format = (*p & 0x40) != 0;
        int packet_tag;
        size_t packet_len;

        if (new_format) 
        {
            packet_tag = *p & 0x3F;
            p++;

            size_t lh;
            packet_len = read_new_pkt_len(p, (size_t)(end - p), &lh);
            
            if (lh == 0 && packet_len == 0)  
            {
                return -1;
            }
            
            p += lh;
        } 
        else 
        {
            int len_type = *p & 0x03;
            packet_tag   = (*p >> 2) & 0x0F;
            p++;

            switch (len_type) 
            {
                case 0:
                    packet_len = *p++;
                    break;
                
                case 1:
                    packet_len = ((size_t)p[0] << 8) | p[1];
                    p += 2;
                    break;
                
                    case 2:
                    packet_len = ((size_t)p[0] << 24) | ((size_t)p[1] << 16) | ((size_t)p[2] <<  8) | p[3];
                    p += 4;
                    break;
                
                default: 
                    packet_len = (size_t)(end - p);
                    break;
            }
        }

        const uint8_t *body = p;
        const uint8_t *body_end = p + packet_len;

        if (body_end > end) 
        {
            fprintf(stderr, "pkesk_parse: packet goes beyond end of data\n");
            return -1;
        }
        p = body_end;

        if (packet_tag == 1) 
        {
            return parse_pkesk_body(body, packet_len, out);
        }
    }

    fprintf(stderr, "pkesk_parse: PKESK (tag=1) package not found\n");
    
    return -1;
}