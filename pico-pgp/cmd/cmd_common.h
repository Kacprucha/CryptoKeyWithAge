#ifndef CMD_COMMON_H
#define CMD_COMMON_H

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <mbedtls/sha1.h>

static inline void compute_fingerprint(const uint8_t *xy64, uint8_t *fingerprint_out)
{
    mbedtls_sha1_context ctx;
    mbedtls_sha1_init(&ctx);
    mbedtls_sha1_starts(&ctx);
    mbedtls_sha1_update(&ctx, xy64, 64);
    mbedtls_sha1_finish(&ctx, fingerprint_out);
    mbedtls_sha1_free(&ctx);
}

/* 
* Read the entire file into the allocated buffer. The caller does free(). 
*/
static inline uint8_t *read_file(const char *path, size_t *out_len)
{
    FILE *f = fopen(path, "rb");
    if (!f) { perror(path); return NULL; }

    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    rewind(f);

    if (sz < 0) 
    { 
        fclose(f); 
        return NULL; 
    }

    uint8_t *buf = (uint8_t *)malloc((size_t)sz + 1);
    if (!buf) 
    { 
        fclose(f); 
        return NULL; 
    }

    if ((size_t)sz > 0 && fread(buf, 1, (size_t)sz, f) != (size_t)sz) 
    {
        free(buf); fclose(f); return NULL;
    }

    fclose(f);
    *out_len = (size_t)sz;
    
    return buf;
}

/* 
* Write buffer to file. Returns 0 on success. 
*/
static inline int write_file(const char *path, const uint8_t *data, size_t len)
{
    FILE *f = fopen(path, "wb");
    if (!f) { perror(path); return -1; }

    if (len > 0 && fwrite(data, 1, len, f) != len) 
    {
        fclose(f); return -1;
    }
    
    fclose(f);
    
    return 0;
}

/* 
* Print hex bytes to stderr (for debugging) 
*/
static inline void dump_hex(const char *label, const uint8_t *data, size_t len)
{
    fprintf(stderr, "  [DBG] %s: ", label);
    
    for (size_t i = 0; i < len; i++) 
    {
        fprintf(stderr, "%02X", data[i]);
    }
    
    fprintf(stderr, "\n");
}

#endif 