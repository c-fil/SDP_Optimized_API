#include <stdbool.h>

typedef struct core_time_{
	uint64_t now;  ///< current UNIX time in seconds
	bool now_initialized;  ///< time was initialized
}core_time_t;

void se3c0_time_set(uint64_t t);
void se3c0_time_inc();
uint64_t se3c0_time_get();
bool sec0_now_initialized_get();
void se3c0_time_init();
