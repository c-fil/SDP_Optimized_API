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

SE3_COMM_STATUS comm; //pointer to se3_core structure



/** \brief SDIO read/write request buffer context */
typedef struct s3_storage_range_ {
	uint8_t* buf;
	uint32_t first;
	uint32_t count;
} s3_storage_range;


#ifndef se3_serial_def
#define se3_serial_def
typedef struct SE3_SERIAL_ {
    uint8_t data[SE3_SERIAL_SIZE];
    bool written;  ///< Indicates whether the serial number has been set (by FACTORY_INIT)
} SE3_SERIAL;
#endif

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


#endif

const uint8_t se3_hello[SE3_HELLO_SIZE];

// ---- crypto ----

#define SE3_SESSIONS_BUF (32*1024)  ///< session buffer size
#define SE3_SESSIONS_MAX 100  ///< maximum number of sessions


void se3_communication_init(req_header * req_hdr_comm, resp_header* resp_hdr_comm, SE3_SERIAL* serial_comm);



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
/** \brief Check if block contains the magic sequence
 *  \param buf pointer to block data HOLAAAAAA
 *  \return true if the block contains the magic sequence, otherwise false
 *
 *  Check if a block of data contains the magic sequence, used to initialize the special
 *    protocol file.
 */
bool block_is_magic(const uint8_t* buf);
/** \brief Check if block belongs to the special protocol file
 *  \param block block number
 *  \return the index of the corresponding protocol file block, or -1 if the block does not
 *    belong to the protocol file.
 *
 *  The special protocol file is made up of multiple blocks. Each block is mapped to a block
 *    on the physical storage
 */
int find_magic_index(uint32_t block);
/** \brief add request to SDIO read/write buffer
 *  \param range context; the count field must be initialized to zero on first usage
 *  \param lun parameter from USB handler
 *  \param buf pointer to request data
 *  \param block request block index
 *  \param direction read or write
 *
 *  Contiguous requests are processed with a single call to the SDIO interface, as soon as
 *    a non-contiguous request is added.
 */
int32_t se3_storage_range_add(s3_storage_range* range, uint8_t lun, uint8_t* buf, uint32_t block, uint32_t direction);
/** \brief Handle request for incoming protocol block
 *  \param index index of block in the special protocol file
 *  \param blockdata data
 *
 *  Handle a single block belonging to a protocol request. The data is stored in the
 *    request buffer. As soon as the request data is received completely, the device
 *    will start processing the request
 */
void handle_req_recv(int index, const uint8_t* blockdata);
/** \brief Handle request for outgoing protocol block
 *  \param index index of block in the special protocol file
 *  \param blockdata output data
 *
 *  Output a single block of a protocol response. If the response is ready,
 *    the data is taken from the response buffer. Otherwise the 'not ready' state is
 *    returned.
 */
void handle_resp_send(int index, uint8_t* blockdata);

