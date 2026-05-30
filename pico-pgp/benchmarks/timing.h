#ifndef TIMING_H
#define TIMING_H

#include <time.h>
#include <linux/time.h>

static double now_ms(void) 
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000.0 + ts.tv_nsec / 1e6;
}

#endif