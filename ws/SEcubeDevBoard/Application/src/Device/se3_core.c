#include "se3_core.h"
#include "se3c0def.h"
#include "se3_rand.h"
#include "se3c0.h"
#include "se3c1.h"
#include "se3_flash.h"
#include "se3_cmd.h"

//////
//L0//
//////

SE3_COMM_STATUS comm;
req_header req_hdr;
resp_header resp_hdr;


uint8_t se3_sessions_buf[SE3_SESSIONS_BUF];
uint8_t* se3_sessions_index[SE3_SESSIONS_MAX];


void se3_core_start(){

	while(1){
		//wait for new request/command and execute it
		while(!comm.req_ready);

		comm.resp_ready = false;
		se3_cmd_execute(comm, req_hdr, resp_hdr);
		comm.req_ready = false;
		comm.resp_ready = true;
	}

}

void core_init()
{
    memset(&req_hdr,0,sizeof(req_header));
    memset(&resp_hdr,0,sizeof(resp_header));
    se3_communication_init(&comm, &req_hdr, &resp_hdr);
}
