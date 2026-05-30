#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <mbedtls/sha1.h>
#include "get_pub_key.h"
#include "../device/device.h"
#include "../device/protocol.h"

int cmd_export_pubkey(int argc, char *argv[]) 
{
    const char *port = "/dev/ttyACM0";
    int slot = 0;

    for (int i = 0; i < argc; i++) 
    {
        if (strcmp(argv[i], "--slot") == 0 && i + 1 < argc) 
        {
            slot = atoi(argv[++i]);
        }
        else if (strcmp(argv[i], "--port") == 0 && i + 1 < argc) 
        {
            port = argv[++i];
        }
    }

    printf("[*] Connecting to Pico on %s...\n", port);
    int fd = device_open(port);
    if (fd < 0) 
    {
        perror("device_open");
        return 1;
    }

    uint8_t  xy64[64];
    uint16_t xy_len = 0;
    uint8_t  slot_byte = (uint8_t)slot;

    if (device_send_cmd(fd, CMD_GET_PUBLIC_KEY, &slot_byte, 1, NULL, xy64, &xy_len) != 0 || xy_len != 64) 
    {
        fprintf(stderr, "Error fetching public key from slot %d\n", slot);
        device_close(fd);
        return 1;
    }
    device_close(fd);

    printf("[*] Public key P-256 (slot %d):\n", slot);
    printf("    X: ");
    
    for (int i = 0; i < 32; i++) 
    {
        printf("%02x", xy64[i]);
    }
    
    printf("\n    Y: ");
    
    for (int i = 0; i < 32; i++) 
    {
        printf("%02x", xy64[32 + i]);
    }
    
    printf("\n");

    return 0;
}