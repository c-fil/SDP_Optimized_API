#pragma once
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>


//#include "se3c1def.h"
//#include "se3_common.h"
///////
#include "se3_comm_core.h"
#include "se3_disp_core.h"
#include "se3_core_time.h"
#include "se3_memory.h"
#include "se3_keys.h"
///////
#include "crc16.h"
///////

#if defined(_MSC_VER)
#define SE3_ALIGN_16 __declspec(align(0x10))
#elif defined(__GNUC__)
#define SE3_ALIGN_16 __attribute__((aligned(0x10)))
#else
#define SE3_ALIGN_16
#endif

#define SE3_FLASH_SIGNATURE_ADDR  ((uint32_t)0x08020000)
#define SE3_FLASH_SIGNATURE_SIZE  ((size_t)0x40)

////
//L0
////
#ifndef se3_req_resp_header_define
#define se3_req_resp_header_define
/** \brief serial number data and state */
//typedef struct SE3_SERIAL_ {
//    uint8_t data[SE3_SERIAL_SIZE];
//    bool written;  ///< Indicates whether the serial number has been set (by FACTORY_INIT)
//} SE3_SERIAL;

/** \brief decoded request header */
typedef struct se3c0_req_header_ {
    uint16_t cmd;
    uint16_t cmd_flags;
    uint16_t len;
#if SE3_CONF_CRC
    uint16_t crc;
#endif
    uint32_t cmdtok[SE3_COMM_N - 1];
} req_header;

/** \brief response header to be encoded */
typedef struct se3c0_resp_header_ {
    uint16_t ready;
    uint16_t status;
    uint16_t len;
#if SE3_CONF_CRC
    uint16_t crc;
#endif
    uint32_t cmdtok[SE3_COMM_N - 1];
} resp_header;
#endif


/** L0 command handler */
typedef uint16_t(*se3_cmd_func)(uint16_t, const uint8_t*, uint16_t*, uint8_t*);

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


void core_init();

void se3_core_start();

void login_cleanup();

void se3_cmd_execute();
uint16_t se3_exec(se3_cmd_func handler);
uint16_t invalid_cmd_handler(uint16_t req_size, const uint8_t* req, uint16_t* resp_size, uint8_t* resp);

/*
 * COMMANDS
 */
//L0
/** \brief ECHO command handler
 *
 *  Send back received data
 */
uint16_t echo(uint16_t req_size, const uint8_t* req, uint16_t* resp_size, uint8_t* resp);

/** \brief FACTORY_INIT command handler
 *
 *  Initialize device's serial number
 */
uint16_t factory_init(uint16_t req_size, const uint8_t* req, uint16_t* resp_size, uint8_t* resp);

/** \brief FACTORY_INIT command handler
 *
 *  Reset USEcube to boot mode
 */
uint16_t bootmode_reset(uint16_t req_size, const uint8_t* req, uint16_t* resp_size, uint8_t* resp);

/** \brief L0 command which executes an L1 command
 *
 *  This handler also manages encryption and login token check
 */
uint16_t sec_cmd(uint16_t req_size, const uint8_t* req, uint16_t* resp_size, uint8_t* resp);

//L1
/** \brief Command to handle error in requested commands
 *
 */
uint16_t cmd_error(uint16_t req_size, const uint8_t* req, uint16_t* resp_size, uint8_t* resp);

/////////
////LOGIN
/////////
/*
    Challenge-based authentication

	Password-Based Key Derivation Function 2
			PBKDF2(PRF, Password, Salt, c, dkLen)

	cc1     client(=host) challenge 1
			random(32)
	cc2     client(=host) challenge 2
			random(32)
	sc      server(=device) challenge
			random(32)
	cresp   client(=host) response
			PBKDF2(HMAC-SHA256, pin, sc, SE3_L1_CHALLENGE_ITERATIONS, SE3_CHALLENGE_SIZE)
	sresp   server(=device) response
			PBKDF2(HMAC-SHA256, pin, cc1, SE3_L1_CHALLENGE_ITERATIONS, SE3_CHALLENGE_SIZE)
	key     session key for enc/auth of L1 protocol
			PBKDF2(HMAC-SHA256, pin, cc2, 1, SE3_L1_PIN_SIZE)

	L1_challenge (not encrypted)
		host
			generate cc1,cc2
			send cc1,cc2
		device
			generate sc
			compute sresp, cresp, key
			send sresp
	L1_login (encrypted with key)
		host
			compute sresp, cresp, key
			check sresp
			send cresp
		device
			check cresp
			send token  <- the token is transmitted encrypted
*/
/** \brief L1 CHALLENGE command handler
 *
 *  Get a login challenge from the device
 *  challenge : (cc1[32], cc2[32], access:ui16) => (sc[32], sresp[32])
 *
 */
uint16_t challenge(uint16_t req_size, const uint8_t* req, uint16_t* resp_size, uint8_t* resp);

/** \brief L1 LOGIN command handler
 *
 *  Respond to challenge and complete the login
 *  login : (cresp[32]) => (tok[16])
 */
uint16_t cmd_login(uint16_t req_size, const uint8_t* req, uint16_t* resp_size, uint8_t* resp);

/** \brief L1 LOGOUT command handler
 *
 *  Log out and release resources
 *  logout : () => ()
 */
uint16_t logout(uint16_t req_size, const uint8_t* req, uint16_t* resp_size, uint8_t* resp);

////KEYS
/** \brief L1 KEY_EDIT
 *
 *  Insert, delete or update a key
 *  key_edit : (op:ui16, id:ui32, validity:ui32, data-len:ui16, name-len:ui16, data[data-len], name[name-len]) => ()
 */
uint16_t key_edit(uint16_t req_size, const uint8_t* req, uint16_t* resp_size, uint8_t* resp);

/** \brief L1 KEY_LIST
 *
 *  Get a list of keys in the device
 *  key_list : (skip:ui16, nmax:ui16, salt[32]) => (count:ui16, keyinfo0, keyinfo1, ...)
 *  keyinfo: (id:ui32, validity:ui32, data-len:ui16, name-len:ui16, name[name-len], fingerprint[32])
 */
uint16_t key_list(uint16_t req_size, const uint8_t* req, uint16_t* resp_size, uint8_t* resp);

/////////
////CONFIG
/////////
/** \brief L1 CONFIG command handler
 *
 *  Get or set a configuration record
 *  config : (type:ui16, op:ui16, value[32]) => (value[32])
 */
uint16_t config(uint16_t req_size, const uint8_t* req, uint16_t* resp_size, uint8_t* resp);




