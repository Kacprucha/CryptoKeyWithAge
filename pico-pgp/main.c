#include <stdio.h>
#include <string.h>
#include "cmd/get_pub_key.h"
#include "cmd/encrypt.h"
#include "cmd/decrypt.h"

static void usage(const char *prog) {
    fprintf(stderr,
        "Usage: %s <command> [options]\n"
        "\n"
        "Commands:\n"
        "  export-pubkey --slot N [--port /dev/ttyACM0]\n"
        "            Export public key from Pico slot\n"
        "\n"
        "  encrypt   <file> [--port /dev/ttyACM0]\n"
        "            Encrypt file with gpg (uses pico@device certificate)\n"
        "\n"
        "  decrypt   <file.pgp> [--slot N] [--port /dev/ttyACM0]\n"
        "            Decrypt file with hardware ECDH (Pico) + mbedTLS\n",
        prog);
}

int main(int argc, char *argv[]) 
{
    if (argc < 2) 
    { 
        usage(argv[0]); 
        return 1; 
    }

    if (strcmp(argv[1], "export-pubkey") == 0) 
    {
        return cmd_export_pubkey(argc - 2, argv + 2);
    }

    if (strcmp(argv[1], "encrypt") == 0) 
    {
        return cmd_encrypt(argc - 2, argv + 2, NULL);
    }

    if (strcmp(argv[1], "decrypt") == 0) 
    {
        return cmd_decrypt(argc - 2, argv + 2, NULL);
    }

    fprintf(stderr, "Unknown command: %s\n", argv[1]);
    usage(argv[0]);
    
    return 1;
}