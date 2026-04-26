#include "device.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main (int argc, char *argv[]) 
{
    const char *port = argc > 1 ? argv[1] : "/dev/ttyACM0";
    int fd = device_open(port);

    if (fd < 0) 
    {
        fprintf(stderr, "Failed to open port at %s\n", port);
        return EXIT_FAILURE;
    }

    uint8_t resp[MAX_PAYLOAD];
    uint16_t resp_len = 0;

    if (device_send_cmd (fd, CMD_GET_STATUS, NULL, 0, NULL, resp, &resp_len) == 0) 
    {
        printf("Device status: %.*s\n", resp_len, resp);
    } 
    else 
    {
        fprintf(stderr, "Failed to get device status\n");
        device_close(fd);
        return EXIT_FAILURE;
    }

    device_close(fd);
    printf("Test completed successfully\n");
    return EXIT_SUCCESS;
}