#pragma once
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>



//#include "se3c1def.h"
//#include "se3_common.h"
///////
#include "se3_comm_core.h"


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


void core_init();

void se3_core_start();
