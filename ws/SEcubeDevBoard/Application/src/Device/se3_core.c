#include "se3_core.h"

////
//L0
////
SE3_FLASH_INFO flash;
SE3_COMM_STATUS comm;
//SE3_SERIAL serial;
//req_header req_hdr;
//resp_header resp_hdr;
uint16_t hwerror;

////
//L1
////
SE3_LOGIN_STATUS login;
SE3_RECORD_INFO records[SE3_RECORD_MAX];
se3_mem sessions;
uint16_t sessions_algo[SE3_SESSIONS_MAX];

//uint8_t se3_comm_request_buffer[SE3_COMM_N*SE3_COMM_BLOCK];
//uint8_t se3_comm_response_buffer[SE3_COMM_N*SE3_COMM_BLOCK];



uint8_t se3_sessions_buf[SE3_SESSIONS_BUF];
uint8_t* se3_sessions_index[SE3_SESSIONS_MAX];


void core_init()
{
	/*
	 * L0 INIT
	 */
    memset(&comm, 0, sizeof(SE3_COMM_STATUS));
    memset(&flash, 0, sizeof(SE3_FLASH_INFO));
    //TODO: MEMSET DI QUALSIASI COSA
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

    /*
     * L1 INIT
     */
    memset((void*)&login, 0, sizeof(SE3_LOGIN_STATUS));
    memset((void*)&records[0], 0, sizeof(SE3_RECORD_INFO));
    memset((void*)&records[1], 0, sizeof(SE3_RECORD_INFO));
    memset((void*)&sessions, 0, sizeof(se3_mem));
    memset((void*)&sessions_algo, 0, SE3_SESSIONS_MAX*sizeof(uint16_t));


    records[SE3_RECORD_TYPE_USERPIN].read_access = SE3_ACCESS_MAX;
    records[SE3_RECORD_TYPE_USERPIN].write_access = SE3_ACCESS_ADMIN;

    records[SE3_RECORD_TYPE_ADMINPIN].read_access = SE3_ACCESS_MAX;
    records[SE3_RECORD_TYPE_ADMINPIN].write_access = SE3_ACCESS_ADMIN;

    se3_mem_init(
        &(sessions),
        SE3_SESSIONS_MAX, se3_sessions_index,
        SE3_SESSIONS_BUF, se3_sessions_buf);

    se3c1_login_cleanup();
}

void login_cleanup()
{
    size_t i;
    se3_mem_reset(&(sessions));
    login.y = false;
    login.access = 0;
    login.challenge_access = SE3_ACCESS_MAX;
    login.cryptoctx_initialized = false;
    //memset(se3c1.login.key, 0, SE3_L1_KEY_SIZE);
    memcpy(login.key, se3_magic, SE3_L1_KEY_SIZE);
    memset(login.token, 0, SE3_L1_TOKEN_SIZE);
    for (i = 0; i < SE3_SESSIONS_MAX; i++) {
        sessions_algo[i] = SE3_ALGO_INVALID;
    }
}

/*
 * Type stands for user access [0 admin 1 user]
 * TODO: no sense
 */
bool record_get(uint16_t type, uint8_t* data)
{
    se3_flash_it it;
    if (type >= SE3_RECORD_MAX) {
        return false;
    }
    se3_flash_it_init(&it);
    if (!se3c1_record_find(type, &it)) {
        return false;
    }
    memcpy(data, it.addr + SE3_RECORD_OFFSET_DATA, SE3_RECORD_SIZE);
    return true;
}

bool record_set(uint16_t type, const uint8_t* data)
{
    se3_flash_it it;
    bool found = false;
    se3_flash_it it2;
    uint8_t tmp[2];
    if (type >= SE3_RECORD_MAX) {
        return false;
    }
    se3_flash_it_init(&it);
    if (se3c1_record_find(type, &it)) {
        found = true;
    }

    // allocate new flash block
    memcpy(&it2, &it, sizeof(se3_flash_it));
    if (!se3_flash_it_new(&it2, SE3_FLASH_TYPE_RECORD, SE3_RECORD_SIZE_TYPE + SE3_RECORD_SIZE)) {
        return false;
    }
    // write record type and data
    if (!se3_flash_it_write(&it2, SE3_RECORD_OFFSET_DATA, data, SE3_RECORD_SIZE)) {
        return false;
    }
    SE3_SET16(tmp, 0, type);
    if (!se3_flash_it_write(&it2, SE3_RECORD_OFFSET_TYPE, tmp, SE3_RECORD_SIZE_TYPE)) {
        return false;
    }

    if (found) {
        // delete previously found flash block
        if (!se3_flash_it_delete(&it)) {
            return false;
        }
    }

    return true;
}

bool record_find(uint16_t record_type, se3_flash_it* it)
{
    uint16_t it_record_type = 0;
    while (se3_flash_it_next(it)) {
        if (it->type == SE3_FLASH_TYPE_RECORD) {
            SE3_GET16(it->addr, SE3_RECORD_OFFSET_TYPE, it_record_type);
            if (it_record_type == record_type) {
                return true;
            }
        }
    }
    return false;
}

