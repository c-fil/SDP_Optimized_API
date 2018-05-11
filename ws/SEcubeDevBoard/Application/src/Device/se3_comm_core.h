#pragma once
#include "stdbool.h"
#include "se3_flash.h"
#include "se3c0def.h"
#include "se3_common.h"

#ifndef CUBESIM
#include <se3_sdio.h>
#endif



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

typedef struct SE3_SERIAL_ {
    uint8_t data[SE3_SERIAL_SIZE];
    bool written;  ///< Indicates whether the serial number has been set (by FACTORY_INIT)
} SE3_SERIAL;

#endif

const uint8_t se3_hello[SE3_HELLO_SIZE] = {
	'H', 'e', 'l', 'l', 'o', ' ', 'S', 'E',
    'c', 'u', 'b', 'e', 0, 0, 0, 0,
    0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0
};

// ---- crypto ----
enum {
	SE3_SESSIONS_BUF = (32*1024),  ///< session buffer size
	SE3_SESSIONS_MAX = 100  ///< maximum number of sessions
};

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
int32_t se3_storage_range_add(s3_storage_range* range, uint8_t lun, uint8_t* buf, uint32_t block, enum s3_storage_range_direction direction);
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

bool record_set(uint16_t type, const uint8_t* data);

bool record_get(uint16_t type, uint8_t* data);

bool record_find(uint16_t record_type, se3_flash_it* it);

/** \brief Initialize flash
 *
 *  Selects the active flash sector or initializes one
 */
bool se3_flash_init();

/** \brief Initialize flash iterator
 *
 *  \param it flash iterator structure
 */
void se3_flash_it_init(se3_flash_it* it);

/** \brief Increment flash iterator
 *
 *  Increment iterator and read information of the next node in flash
 *  \param it flash iterator structure
 *  \return false if end of iteration, else true
 */
bool se3_flash_it_next(se3_flash_it* it);

/** \brief Allocate new node
 *
 *  Allocates a new node in the flash and points the iterator to the new node.
 *  \param it flash iterator structure
 *  \param type type of the new flash node
 *  \param size size of the data in the new flash node
 *  \return true if the function succedes, false if there is no more space, or a flash operation fails
 */
bool se3_flash_it_new(se3_flash_it* it, uint8_t type, uint16_t size);

/** \brief Write to flash node
 *
 *  Write data to flash node.
 *  \param it flash iterator structure
 *  \param off offset of data
 *  \param data pointer to data to be written
 *  \param size size of data to be written
 */
bool se3_flash_it_write(se3_flash_it* it, uint16_t off, const uint8_t* data, uint16_t size);

/** \brief Delete flash node
 *
 *  Delete a flash node and its data
 *  \param it flash iterator structure
 *  \return true on success, else false
 */
bool se3_flash_it_delete(se3_flash_it* it);

/** \brief Delete flash node by index
 *
 *  Delete a flash node given its index
 *  \param pos the index of the node
 *  \return true on success, else false
 */
bool se3_flash_pos_delete(size_t pos);

/** \brief Get unused space
 *
 *  Get unused space in the flash memory, including the space marked as invalid.
 *  If space is available, it does not mean that flash sectors will not be swapped.
 *  \return unused space in bytes
 */
size_t se3_flash_unused();

/** \brief Check if enough space for new node
 *
 *  Check if there is enough space
 *  \param size size of the data to be stored inside the new node
 *  \return true if the node will fit into the flash, else false
 */
bool se3_flash_canfit(size_t size);

/** \brief Initialize flash structures
 *
 *  Initializes the structures for flash management, selecting a sector and its base address.
 *  \param sector active sector number
 *  \param base active sector base address
 */
void se3_flash_info_setup(uint32_t sector, const uint8_t* base);

/** \brief Initialize flash structures
 *
 *  Reset the USEcube device to boot mode by erasing the signature - zeroise.
 *  \param addr signature starting address
 *  \param size signature size
 */
bool se3_flash_bootmode_reset(uint32_t addr, size_t size);

