#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include "encrypt.h"
#include "../benchmarks/timing.h"

int cmd_encrypt(int argc, char *argv[], double *out_time_ms, size_t *out_enc_bytes) 
{
    const char *input_path = NULL;
    bool logger_enabled = true;

    for (int i = 0; i < argc; i++) 
    {
        if (strcmp(argv[i], "--port") == 0 && i + 1 < argc) 
        {
            i++;
        }
        else if (strcmp(argv[i], "--logger") == 0 && i + 1 < argc) 
        {
            logger_enabled = strcmp(argv[++i], "true") == 0;
        }
        else if (argv[i][0] != '-' && input_path == NULL)
        {
            input_path = argv[i];
        }
    }

    if (!input_path) 
    {
        fprintf(stderr, "Usage: pico-pgp encrypt <file>\n");
        return 1;
    }

    char check_cmd[512];
    snprintf(check_cmd, sizeof(check_cmd), "gpg --list-keys pico@device > /dev/null 2>&1");
    
    if (system(check_cmd) != 0) {
        fprintf(stderr,
            "Error: key 'pico@device' is not in the GPG keyring.\n"
            "Run first:\n"
            "\tpico-pgp gen-cert --slot 0 --out pico_cert.pgp\n"
            "\tgpg --import pico_cert.pgp\n");
        
        return 1;
    }

    char out_path[512];
    snprintf(out_path, sizeof(out_path), "%s.pgp", input_path);

    char gpg_cmd[1024];
    snprintf(gpg_cmd, sizeof(gpg_cmd),
        "gpg --trust-model always "
        "    --encrypt "
        "    -r pico@device "
        "    --output \"%s\" "
        "    --batch --yes "
        "    \"%s\"",
        out_path, input_path);
    
    if (logger_enabled) 
    {
        printf("[*] GPG encryption...\n");
        printf("\tCommand: %s\n", gpg_cmd);
    }

    double t0 = now_ms();
    int ret = system(gpg_cmd);
    double elapsed = now_ms() - t0;

    if (ret != 0) 
    {
        fprintf(stderr, "GPG Error: exit code %d\n", ret);
        return 1;
    }

    if (out_time_ms) 
    { 
        *out_time_ms = elapsed;
    }

    if (out_enc_bytes)
    {
        FILE *f = fopen(out_path, "rb");
        if (f)
        {
            fseek(f, 0, SEEK_END);
            *out_enc_bytes = (size_t)ftell(f);
            fclose(f);
        }
        else
        {
            *out_enc_bytes = 0;
        }
    }

    if (logger_enabled) 
    {
        printf("[+] Encrypted: %s\n", out_path);
    }

    return 0;
}