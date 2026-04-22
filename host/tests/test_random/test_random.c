#include "device.h"
#include "protocol.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int main (int argc, char *argv[]) 
{
    const char *port = argc > 1 ? argv[1] : "/dev/ttyACM0";
    int fd = device_open (port);
    if (fd < 0) 
    {
        perror("Failed to open device");
        return 1;
    }

    uint8_t request[] = { 32 }; // Request 32 bytes of random data
    uint8_t response[MAX_PAYLOAD];
    uint16_t response_len = 0;

    if (device_send_cmd (fd, CMD_GET_RANDOM, request, 1, response, &response_len) != 0) 
    {
        fprintf(stderr, "Failed to send command or receive response\n");
        device_close (fd);
        return 1;
    }

    printf("Received %u bytes of random data:\n", response_len);
    for (uint16_t i = 0; i < response_len; i++) 
    {
        printf("%02X ", response[i]);
    }
    printf("\n");

    bool is_test_pattern = true;
    for (int i = 0; i < response_len - 1; i += 4) {
        if (response[i] != 0xFF && response[i+1] != 0xFF && response[i+2] != 0x00 && response[i+3] != 0x00) {
            is_test_pattern = false;
            break;
        }
    }

    if (is_test_pattern) 
    {
        printf ("INFO: Config Zone not locked, received test pattern instead of random data\n");
        device_close (fd);
        return 0;
    }

    uint8_t seen[256] = {0};
    for (int i = 0; i < response_len; i++) 
    {
        seen[response[i]]++;
    }

    int unique_count = 0;
    for (int i = 0; i < 256; i++) 
    {
        if (seen[i] == 1) 
        {
            unique_count++;
        }
    }

    if (unique_count < 10) 
    {
        fprintf(stderr, "FAIL: small entropy detected (only %d unique bytes)\n", unique_count);
        device_close (fd);
        return 2;
    }

    printf("PASS: sufficient entropy detected (%d unique bytes)\n", unique_count);
    device_close (fd);
    return 0;
}