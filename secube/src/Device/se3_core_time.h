#include <stdbool.h>
#include <stdint.h>


typedef struct core_time_{
	uint64_t now;  ///< current UNIX time in seconds
	bool now_initialized;  ///< time was initialized
}core_time_t;

void time_set(uint64_t t);
void time_inc();
uint64_t time_get();
bool now_initialized_get();
void time_init();
