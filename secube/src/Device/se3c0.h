/**
 *  \file se3c0.h
 *  \author Nicola Ferri
 *  \brief L0 structures and functions
 */

#pragma once
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "sha256.h"
#include "aes256.h"

#include "se3c0def.h"
#include "se3_common.h"

#if defined(_MSC_VER)
#define SE3_ALIGN_16 __declspec(align(0x10))
#elif defined(__GNUC__)
#define SE3_ALIGN_16 __attribute__((aligned(0x10)))
#else
#define SE3_ALIGN_16
#endif

void se3c0_init();
uint64_t se3c0_time_get();
void se3c0_time_set(uint64_t t);
void se3c0_time_inc();

const uint8_t se3_hello[SE3_HELLO_SIZE];

#define SE3_BMAP_MAKE(n) ((uint32_t)(0xFFFFFFFF >> (32 - (n))))

/** \brief structure holding host-device communication status and buffers
 *
 *  req_ready and resp_ready must be volatile, otherwise -O3 optimization will not work.
 */
typedef struct SE3_COMM_STATUS_ {
    // magic
    bool magic_ready;  ///< magic written flag
    uint32_t magic_bmap;  ///< bit map of written magic sectors

    // block map
    uint32_t blocks[SE3_COMM_N];  ///< map of blocks
    uint32_t block_guess;  ///< guess for next block that will be accessed
    bool locked;  ///< prevent magic initialization

    // request
    volatile bool req_ready;  ///< request ready flag
    uint32_t req_bmap;  ///< map of received request blocks
    uint8_t* req_data;  ///< received data buffer
    uint8_t* req_hdr;   ///< received header buffer

    // response
    volatile bool resp_ready;  ///< response ready flag
    uint32_t resp_bmap;  ///< map of sent response blocks
    uint8_t* resp_data;  ///< buffer for data to be sent
    uint8_t* resp_hdr;  ///< buffer for header to be sent
} SE3_COMM_STATUS;

/** \brief Flash management structure */
typedef struct SE3_FLASH_INFO_ {
    uint32_t sector;  ///< active sector number
    const uint8_t* base;
    const uint8_t* index;
    const uint8_t* data;
    size_t first_free_pos;
    size_t used;
    size_t allocated;
} SE3_FLASH_INFO;

/** \brief serial number data and state */
typedef struct SE3_SERIAL_ {
    uint8_t data[SE3_SERIAL_SIZE];
    bool written;  ///< Indicates whether the serial number has been set (by FACTORY_INIT)
} SE3_SERIAL;

/** \brief decoded request header */
typedef struct se3c0_req_header_ {
    uint16_t cmd;
    uint16_t cmd_flags;
    uint16_t len;
#if SE3_CONF_CRC
    uint16_t crc;
#endif
    uint32_t cmdtok[SE3_COMM_N - 1];
} se3c0_req_header;

/** \brief response header to be encoded */
typedef struct se3c0_resp_header_ {
    uint16_t ready;
    uint16_t status;
    uint16_t len;
#if SE3_CONF_CRC
    uint16_t crc;
#endif
    uint32_t cmdtok[SE3_COMM_N - 1];
} se3c0_resp_header;

/** L0 command handler */
typedef uint16_t(*se3_cmd_func)(uint16_t, const uint8_t*, uint16_t*, uint8_t*);

/** \brief L0 globals structure */
typedef struct SE3_L0_GLOBALS_ {
    SE3_SERIAL serial;
    SE3_FLASH_INFO flash;
    SE3_COMM_STATUS comm;
    se3c0_req_header req_hdr;
    se3c0_resp_header resp_hdr;
    union {
        B5_tSha256Ctx sha;
        B5_tAesCtx aes;
    } ctx;
    uint16_t hwerror;

    uint64_t now;  ///< current UNIX time in seconds
	bool now_initialized;  ///< time was initialized
} SE3_L0_GLOBALS;

extern uint8_t se3_comm_request_buffer[SE3_COMM_N*SE3_COMM_BLOCK];
extern uint8_t se3_comm_response_buffer[SE3_COMM_N*SE3_COMM_BLOCK];
extern SE3_L0_GLOBALS se3c0;

