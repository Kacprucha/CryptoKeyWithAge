#include "device.h"
#include <string.h>

int device_open(const char *path) 
{
    int fd = open (path, O_RDWR | O_NOCTTY);

    if (fd < 0)
        return -1;

    struct termios tty;
    
    tcgetattr (fd, &tty);
    cfsetispeed (&tty, B115200);
    cfsetospeed (&tty, B115200);
    
    tty.c_cflag = CS8 | CREAD | CLOCAL;
    tty.c_iflag = 0;
    tty.c_oflag = 0;
    tty.c_lflag = 0;
    tty.c_cc[VMIN] = 0;
    tty.c_cc[VTIME] = 20;
    
    tcsetattr (fd, TCSANOW, &tty);    
    
    return fd;
}

int device_send_cmd (int fd, uint8_t cmd, const uint8_t *data, uint16_t data_len, uint8_t *resp_data, uint16_t *resp_len) 
{
    uint8_t frame[FRAME_OVERHEAD + MAX_PAYLOAD];
    size_t frame_len;

    if (!protocol_build_frame (cmd, data, data_len, frame, &frame_len) || 
        write (fd, frame, frame_len) != (ssize_t)frame_len) 
    {
        return -1;
    }

    uint8_t resp[FRAME_OVERHEAD + MAX_PAYLOAD];
    ssize_t n = read (fd, resp, sizeof(resp));

    if (n < (ssize_t)FRAME_OVERHEAD)
        return -1;

    uint8_t resp_cmd;

    return protocol_parse_response (resp, n, &resp_cmd, resp_data, resp_len) ? 0 : -1;
}

void device_close (int fd) 
{
    close (fd);
}