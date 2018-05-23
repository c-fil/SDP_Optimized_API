#pragma once
#include "se3_common.h"
#ifndef CUBESIM
#include <se3_sdio.h>
#endif

/** USB data handlers return values */

#define SE3_PROTO_OK 0  ///< Report OK to the USB HAL
#define SE3_PROTO_FAIL 1  ///< Report FAIL to the USB HAL
#define SE3_PROTO_BUSY 2  ///< Report BUSY to the USB HAL

//Create bit vector of n MSB 0 followed by 32-n ones;
#define SE3_BMAP_MAKE(n) ((uint32_t)(0xFFFFFFFF >> (32 - (n))))
#define SE3_CMD_MAX 16


//#define s3_storage_range_direction
#define range_write 0
#define range_read 1





/** \brief SDIO read/write request buffer context */
typedef struct s3_storage_range_ {
	uint8_t* buf;
	uint32_t first;
	uint32_t count;
} s3_storage_range;


#ifndef se3_req_resp_header_define
#define se3_req_resp_header_define

typedef struct se3c0_req_header_ {
    uint16_t cmd;
    uint16_t cmd_flags;
    uint16_t len;
#if SE3_CONF_CRC
    uint16_t crc;
#endif
    uint32_t cmdtok[SE3_COMM_N - 1];
} req_header;

typedef struct se3c0_resp_header_ {
    uint16_t ready;
    uint16_t status;
    uint16_t len;
#if SE3_CONF_CRC
    uint16_t crc;
#endif
    uint32_t cmdtok[SE3_COMM_N - 1];
} resp_header;

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


#endif

const uint8_t se3_hello[SE3_HELLO_SIZE];

// ---- crypto ----

//#define SE3_SESSIONS_BUF (32*1024)  ///< session buffer size
//#define SE3_SESSIONS_MAX 100  ///< maximum number of sessions


void se3_communication_init();

/** \brief Reset protocol request buffer
 *
 *  Reset the protocol request buffer, making the device ready for a new request.
 */
void se3_proto_request_reset();
/** \brief USB data receive handler
 *
 *  SEcube API requests are filtered and data is stored in the request buffer.
 *  The function also takes care of the initialization of the special protocol file.
 *  Other requests are passed to the SDIO interface.
 */
int32_t se3_proto_recv(uint8_t lun, const uint8_t* buf, uint32_t blk_addr, uint16_t blk_len);
/** \brief USB data send handler
 *
 *  SEcube API requests are filtered and data is sent from the response buffer
 *  Other requests are passed to the SDIO interface.
 */
int32_t se3_proto_send(uint8_t lun, uint8_t* buf, uint32_t blk_addr, uint16_t blk_len);
