#ifndef DECRYPT_H
#define DECRYPT_H

#include <stdbool.h>
#include <stdint.h>

typedef struct {
    int     have_secret;   // 0 = count ECDH on chip and fill; 1 = use cache
    uint8_t shared[32]; 
} pgp_secret_cache_t;

int cmd_decrypt(int argc, char *argv[]);
int pgp_decrypt_core(int fd, const char *input_path, const char *output_path, int slot, const uint8_t fingerprint[20], bool skip_tup, pgp_secret_cache_t *cache, bool logger_enabled, double *out_time_ms);

#endif