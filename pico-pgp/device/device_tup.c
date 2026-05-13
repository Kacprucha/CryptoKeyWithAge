#include "device_tup.h"
#include "device.h"
#include "protocol.h"
#include <unistd.h> 
#include <stdio.h>
#include <string.h>

int pgp_device_send_cmd_tup(int fd, uint8_t cmd, const uint8_t *data, uint16_t data_len, uint8_t *resp_data, uint16_t  *resp_len)
{
    uint8_t  resp_cmd = 0;
    uint16_t raw_len  = 0;

    int rc = device_send_cmd(fd, cmd, data, data_len, &resp_cmd, resp_data, &raw_len);
    if (rc != 0) 
    { 
        return -1;
    }

    if (resp_cmd == cmd && raw_len == 32) 
    {
        *resp_len = raw_len;
        return 0;
    }

    if (resp_cmd != CMD_USER_PRESENCE_PENDING) 
    {
        fprintf(stderr, "[device] Unexpected answer: cmd=0x%02X len=%u\n", resp_cmd, raw_len);
        return -1;
    }

    fprintf(stderr,
        "\n"
        "┌──────────────────────────────────────────────────────────────────┐\n"
        "│  Press the TUP button on Pico,                                   │\n"
        "│  and then press ENTER.                                           │\n"
        "│  (The LED on the Pico lights up when it's waiting for a button)  │\n"
        "└──────────────────────────────────────────────────────────────────┘\n"
        "  [Press ENTER after pressing TUP]: ");
    fflush(stderr);

    int ch;
    while ((ch = getchar()) != '\n' && ch != EOF)
        ; /* consume the remaining signs */

    resp_cmd = 0;
    raw_len  = 0;

    rc = device_send_cmd(fd, cmd, data, data_len, &resp_cmd, resp_data, &raw_len);
    if (rc != 0) 
    {
        return -1;
    }

    if (resp_cmd == cmd && raw_len == 32) 
    {
        *resp_len = raw_len;
        fprintf(stderr, "Autorization OK.\n\n");
        return 0;
    }

    /* Second PENDING or error */
    fprintf(stderr, "[device] Retry failed: cmd=0x%02X len=%u\n", resp_cmd, raw_len);
    return -1;
}