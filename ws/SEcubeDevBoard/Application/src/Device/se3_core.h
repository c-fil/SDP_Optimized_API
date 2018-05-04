#pragma once
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "sha256.h"
#include "aes256.h"

#include "se3c0def.h"
#include "se3c1def.h"
#include "se3_common.h"
///////
#include "se3_comm_core.h"
#include "se3_disp_core.h"
#include "se3_core_time.h"
#include "se3_memory.h"
#include "se3_keys.h"
///////

#if defined(_MSC_VER)
#define SE3_ALIGN_16 __declspec(align(0x10))
#elif defined(__GNUC__)
#define SE3_ALIGN_16 __attribute__((aligned(0x10)))
#else
#define SE3_ALIGN_16
#endif

//Create bit vector of n MSB 0 followed by 32-n ones;
#define SE3_BMAP_MAKE(n) ((uint32_t)(0xFFFFFFFF >> (32 - (n))))



void core_init();
void login_cleanup();
bool record_set(uint16_t type, const uint8_t* data);
bool record_get(uint16_t type, uint8_t* data);
bool record_find(uint16_t record_type, se3_flash_it* it);


////
//L0
////
///** \brief serial number data and state */
//typedef struct SE3_SERIAL_ {
//    uint8_t data[SE3_SERIAL_SIZE];
//    bool written;  ///< Indicates whether the serial number has been set (by FACTORY_INIT)
//} SE3_SERIAL;

/** \brief decoded request header */
//typedef struct se3c0_req_header_ {
//    uint16_t cmd;
//    uint16_t cmd_flags;
//    uint16_t len;
//#if SE3_CONF_CRC
//    uint16_t crc;
//#endif
//    uint32_t cmdtok[SE3_COMM_N - 1];
//} req_header;
//
///** \brief response header to be encoded */
//typedef struct se3c0_resp_header_ {
//    uint16_t ready;
//    uint16_t status;
//    uint16_t len;
//#if SE3_CONF_CRC
//    uint16_t crc;
//#endif
//    uint32_t cmdtok[SE3_COMM_N - 1];
//} resp_header;


///** L0 command handler */
//typedef uint16_t(*se3_cmd_func)(uint16_t, const uint8_t*, uint16_t*, uint8_t*);

//extern uint8_t se3_comm_request_buffer[SE3_COMM_N*SE3_COMM_BLOCK];
//extern uint8_t se3_comm_response_buffer[SE3_COMM_N*SE3_COMM_BLOCK];

/** \brief L0 globals structure */
/*typedef struct SE3_L0_GLOBALS_ {
    union {
        B5_tSha256Ctx sha;
        B5_tAesCtx aes;
    } ctx;

} SE3_L0_GLOBALS;*/



////
//L1
////

/** \brief login status data */
typedef struct SE3_LOGIN_STATUS_ {
    bool y; 						 	///< logged in
    uint16_t access; 				 	///< access level
    uint16_t challenge_access;  	 	///< access level of the last offered challenge
    union {
        uint8_t token[SE3_L1_TOKEN_SIZE];   		///< login token
        uint8_t challenge[SE3_L1_CHALLENGE_SIZE];  	///< login challenge response expected
    };
    uint8_t key[SE3_L1_KEY_SIZE];  		///< session key for protocol encryption
    se3_payload_cryptoctx cryptoctx;  	///< context for protocol encryption
    bool cryptoctx_initialized;  		///< context initialized flag
} SE3_LOGIN_STATUS;

typedef struct SE3_RECORD_INFO_ {
    uint16_t read_access;  ///< required access level for read
    uint16_t write_access;  ///< required access level for write
} SE3_RECORD_INFO;

// ---- records ----
enum {
	SE3_FLASH_TYPE_RECORD = 0xF0  ///< flash node type: record
};

/** \brief Record information */
enum {
	SE3_RECORD_SIZE_TYPE = 2,  ///< record.type field size
	SE3_RECORD_OFFSET_TYPE = 0, ///< record.type field offset
	SE3_RECORD_OFFSET_DATA = 2, ///< record.data field offset
};

// ---- crypto ----
enum {
	SE3_SESSIONS_BUF = (32*1024),  ///< session buffer size
	SE3_SESSIONS_MAX = 100  ///< maximum number of sessions
};


