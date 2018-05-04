#include "se3_core_time.h"

core_time_t core_time;

uint64_t se3c0_time_get()
{
#ifdef CUBESIM
	core_time.now = (uint64_t)time(0);
#endif
    return core_time.now;
}

void se3c0_time_set(uint64_t t)
{
	core_time.now = t;
	core_time.now_initialized = true;
}

bool sec0_now_initialized_get()
{
	return core_time.now_initialized;
}

void se3c0_time_inc()
{
    static unsigned int ms = 0;
    if (++ms == 1000) {
        (core_time.now)++;
        ms = 0;
    }
}

void se3c0_time_init()
{
	core_time.now = 0;
	core_time.now_initialized = false;
}
