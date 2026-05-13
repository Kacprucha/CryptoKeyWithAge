#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include "device.h"
#include "protocol.h"

int main(int argc, char *argv[])
{
    const char *port = (argc > 1) ? argv[1] : "/dev/ttyACM0";

    uint8_t slot = 0;
    if (argc > 2) 
    {
        int slot_arg = atoi(argv[2]);

        if (slot_arg < 0 || slot_arg > 7) 
        {
            fprintf(stderr, "Błąd: slot musi być w zakresie 0-7 (podano: %d)\n", slot_arg);
            return 1;
        }

        slot = (uint8_t)slot_arg;
    }

    int fd = device_open(port);
    if (fd < 0) 
    {
        perror("device_open");
        return 1;
    }

    printf("Getting public key (slot %u)...\n", slot);
    
    uint8_t  pubkey[64] = {0};
    uint16_t pub_len = 0;
    uint8_t  get_pub_cmd[1] = { slot };
    uint8_t  pub_resp_cmd = 0;
    
    if (device_send_cmd(fd, CMD_GET_PUBLIC_KEY, get_pub_cmd, 1, &pub_resp_cmd, pubkey, &pub_len) != 0 || pub_len != 64) 
    {
        fprintf(stderr, "FAIL – nie udało się pobrać klucza publicznego\n");
        device_close(fd);
        return 1;
    }
    
    printf("OK – klucz publiczny pobrany (%u bajtów).\n\n", pub_len);

    uint8_t ecdh_payload[65];
    ecdh_payload[0] = slot;
    memcpy(ecdh_payload + 1, pubkey, 64);

    printf("Step 1: Sending ECDH_REQUEST – expecting PENDING...\n");
    
    uint8_t resp[128] = {0};
    uint16_t resp_len = 0;
    uint8_t resp_cmd = 0;
    
    device_send_cmd(fd, CMD_ECDH_REQUEST, ecdh_payload, 65, &resp_cmd, resp, &resp_len);

    if (resp_cmd != CMD_USER_PRESENCE_PENDING) 
    {
        fprintf(stderr, "FAIL step 1 – PENDING (0x%02X) was expected, got 0x%02X\n", CMD_USER_PRESENCE_PENDING, resp_cmd);
        device_close(fd);
        return 1;
    }

    printf("OK – firmware responded with PENDING.\n\n");

    printf("Step 2: Press the button on the device, then press ENTER...\n");
    getchar();

    printf("Step 3: Retry ECDH_REQUEST – expecting ECDH result (32B)...\n");

    resp_len = 0;
    resp_cmd = 0;
    int r = device_send_cmd(fd, CMD_ECDH_REQUEST, ecdh_payload, 65, &resp_cmd, resp, &resp_len);

    if (r == 0 && resp_len == 32 && resp_cmd == CMD_ECDH_REQUEST) 
    {
        printf("TUP OK – ECDH executed after pressing the button.\n");
    } 
    else 
    {
        fprintf(stderr, "FAIL – cmd=0x%02X, received %uB (expected 32B)\n", resp_cmd, resp_len);
        device_close(fd);
        return 1;
    }

    device_close(fd);
    return 0;
}