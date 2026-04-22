#include "device.h"
#include <string.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <termios.h>
#include <sys/time.h>

#define READ_TIMEOUT_MS  500

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

static ssize_t read_exact(int fd, uint8_t *buf, size_t want, int timeout_ms) 
{
    size_t got = 0;
 
    struct timeval start, now;
    gettimeofday(&start, NULL);
 
    while (got < want) 
    {
        gettimeofday(&now, NULL);
        int elapsed_ms = (int)((now.tv_sec  - start.tv_sec)  * 1000 +
                               (now.tv_usec - start.tv_usec) / 1000);
        if (elapsed_ms >= timeout_ms) 
        {
            fprintf(stderr, "[device] timeout after %dms, read %zu/%zu bytes\n",
                    elapsed_ms, got, want);
            break;
        }
 
        ssize_t n = read(fd, buf + got, want - got);
        if (n > 0) {
            got += (size_t)n;
        } else if (n < 0 && errno != EAGAIN && errno != EINTR) {
            perror("[device] read error");
            break;
        }
        /* n == 0 or EAGAIN → VTIME unit timeout, continue loop */
    }
 
    return (ssize_t)got;
}

int device_send_cmd(int fd, uint8_t cmd, const uint8_t *data, uint16_t data_len, uint8_t *resp_data, uint16_t *resp_len)
{
    // printf("[DEBUG] sending cmd=%02x, len=%u\n", cmd, data_len);
    // for (int i = 0; i < data_len; i++) printf("%02x ", data[i]);
    // printf("\n");
 
    uint8_t frame[FRAME_OVERHEAD + MAX_PAYLOAD];
    size_t  frame_len;
 
    if (!protocol_build_frame(cmd, data, data_len, frame, &frame_len)) 
    {
        fprintf(stderr, "[device] protocol_build_frame failed (data_len=%u, MAX_PAYLOAD=%d)\n",
                data_len, MAX_PAYLOAD);
        return -1;
    }
 
    tcflush(fd, TCIFLUSH);
 
    if (write(fd, frame, frame_len) != (ssize_t)frame_len) 
    {
        perror("[device] write");
        return -1;
    }
 
    uint8_t resp[FRAME_OVERHEAD + MAX_PAYLOAD];
    memset(resp, 0, sizeof(resp));
 
    ssize_t n = read_exact(fd, resp, FRAME_HEADR_SIZE, READ_TIMEOUT_MS);
    if (n < (ssize_t)FRAME_HEADR_SIZE) 
    {
        fprintf(stderr, "[device] no header: %zd/%d bytes read\n",
                n, FRAME_HEADR_SIZE);
        return -1;
    }
 
    if (resp[0] != STX) 
    {
        fprintf(stderr, "[device] no STX: 0x%02X\n", resp[0]);
        return -1;
    }
 
    uint16_t payload_len = (uint16_t)resp[2] | ((uint16_t)resp[3] << 8);
 
    if (payload_len > MAX_PAYLOAD) 
    {
        fprintf(stderr, "[device] payload_len=%u > MAX_PAYLOAD=%d\n",
                payload_len, MAX_PAYLOAD);
        return -1;
    }
 
    size_t rest = payload_len + 4;  /* CRC32 = 4 bayts */
    n = read_exact(fd, resp + FRAME_HEADR_SIZE, rest, READ_TIMEOUT_MS);
    if (n < (ssize_t)rest) 
    {
        fprintf(stderr, "[device] no data: read %zd/%zu bytes\n",
                n, rest);
        return -1;
    }
 
    size_t total = FRAME_HEADR_SIZE + payload_len + 4;
 
    // printf("[DEBUG] Otrzymano %zu bajtow: ", total);
    // for (size_t i = 0; i < total; i++) printf("%02X ", resp[i]);
    // printf("\n");
 
    uint8_t resp_cmd;
    if (!protocol_parse_response(resp, total, &resp_cmd, resp_data, resp_len)) 
    {
        fprintf(stderr, "[device] protocol_parse_response failed\n");
        return -1;
    }
 
    return 0;
}

void device_close (int fd) 
{
    close (fd);
}