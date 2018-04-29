#include "se3_core.h"

SE3_FLASH_INFO flash;
SE3_COMM_STATUS comm;

se3c0_req_header req_hdr;
se3c0_resp_header resp_hdr;

uint16_t hwerror;

//uint8_t se3_comm_request_buffer[SE3_COMM_N*SE3_COMM_BLOCK];
//uint8_t se3_comm_response_buffer[SE3_COMM_N*SE3_COMM_BLOCK];


const uint8_t se3_hello[SE3_HELLO_SIZE] = {
	'H', 'e', 'l', 'l', 'o', ' ', 'S', 'E',
    'c', 'u', 'b', 'e', 0, 0, 0, 0,
    0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0
};

void core_init()
{
    memset(&comm, 0, sizeof(SE3_COMM_STATUS));
    memset(&flash, 0, sizeof(SE3_FLASH_INFO));

    //comm.req_hdr = se3_comm_request_buffer;
    comm.req_hdr = malloc(SE3_COMM_N*SE3_COMM_BLOCK * sizeof (uint8_t));
    //comm.req_data = se3_comm_request_buffer + SE3_REQ_SIZE_HEADER;
    comm.req_data =  comm.req_hdr + SE3_REQ_SIZE_HEADER;
    //comm.resp_hdr = se3_comm_response_buffer;
    comm.resp_hdr = malloc(SE3_COMM_N*SE3_COMM_BLOCK * sizeof (uint8_t));
    //comm.resp_data = se3_comm_response_buffer + SE3_RESP_SIZE_HEADER;
    comm.resp_data =  comm.resp_hdr + SE3_RESP_SIZE_HEADER;

    comm.magic_bmap = SE3_BMAP_MAKE(16); //set 16 LSB bit to 1
    comm.magic_ready = false;
    comm.req_bmap = SE3_BMAP_MAKE(1); //LSB set to 1
    comm.locked = false;
    comm.req_ready = false;
    comm.req_bmap = SE3_BMAP_MAKE(32);
    comm.resp_ready = true;
    comm.resp_bmap = 0;
    se3c0_time_init();
}

