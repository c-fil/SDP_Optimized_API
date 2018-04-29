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
///////
#include "se3_comm_core.h"
#include "se3_core_time.h"
///////
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

//Create bit vector of n MSB 0 followed by 32-n ones;
#define SE3_BMAP_MAKE(n) ((uint32_t)(0xFFFFFFFF >> (32 - (n))))


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

//extern uint8_t se3_comm_request_buffer[SE3_COMM_N*SE3_COMM_BLOCK];
//extern uint8_t se3_comm_response_buffer[SE3_COMM_N*SE3_COMM_BLOCK];

/** \brief L0 globals structure */
/*typedef struct SE3_L0_GLOBALS_ {
    union {
        B5_tSha256Ctx sha;
        B5_tAesCtx aes;
    } ctx;

} SE3_L0_GLOBALS;*/


