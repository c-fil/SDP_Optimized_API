/**
 *  \file se3c0.c
 *  \author Nicola Ferri
 *  \brief L0 structures and functions
 */

#include "se3c0.h"

SE3_L0_GLOBALS se3c0;
uint8_t se3_comm_request_buffer[SE3_COMM_N*SE3_COMM_BLOCK];
uint8_t se3_comm_response_buffer[SE3_COMM_N*SE3_COMM_BLOCK];
const uint8_t se3_hello[SE3_HELLO_SIZE] = {
	'H', 'e', 'l', 'l', 'o', ' ', 'S', 'E',
    'c', 'u', 'b', 'e', 0, 0, 0, 0,
    0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0
};

void se3c0_init()
{
    memset(&se3c0, 0, sizeof(SE3_L0_GLOBALS));
    se3c0.comm.req_hdr = se3_comm_request_buffer;
    se3c0.comm.req_data = se3_comm_request_buffer + SE3_REQ_SIZE_HEADER;
    se3c0.comm.resp_hdr = se3_comm_response_buffer;
    se3c0.comm.resp_data = se3_comm_response_buffer + SE3_RESP_SIZE_HEADER;
    se3c0.comm.magic_bmap = SE3_BMAP_MAKE(16);
    se3c0.comm.magic_ready = false;
    se3c0.comm.req_bmap = SE3_BMAP_MAKE(1);
    se3c0.comm.locked = false;
    se3c0.comm.req_ready = false;
    se3c0.comm.req_bmap = SE3_BMAP_MAKE(32);
    se3c0.comm.resp_ready = true;
    se3c0.comm.resp_bmap = 0;
	se3c0.now_initialized = false;
}

uint64_t se3c0_time_get()
{
#ifdef CUBESIM
    se3c0.now = (uint64_t)time(0);
#endif
    return se3c0.now;
}

void se3c0_time_set(uint64_t t)
{
    se3c0.now = t;
	se3c0.now_initialized = true;
}

void se3c0_time_inc()
{
    static unsigned int ms = 0;
    if (++ms == 1000) {
        (se3c0.now)++;
        ms = 0;
    }
}

