#pragma once

#include "pbkdf2.h"
#include "aes256.h"
#include "crc16.h"
#include "sha256.h"

#include "se3c1def.h"

#include <stdbool.h>
#include "se3_flash.h"

///** \brief Flash key structure
// *
// *  Disposition of the fields within the flash node:
// *  0:3     id
// *  4:7     validity
// *  8:9     data_size
// *  10:11   name_size
// *  12:(12+data_size-1)
// *          data
// *  (12+data_size):(12+data_size+name_size-1)
// *          name
// */
#ifndef se3_flash_key_defined
#define se3_flash_key_defined
typedef struct se3_flash_key_ {
	uint32_t id;
	uint32_t validity;
	uint16_t data_size;
	uint16_t name_size;
	uint8_t* data;
	uint8_t* name;
} se3_flash_key;
#endif


/** \brief Flash node iterator structure */
typedef struct se3_flash_it_ {
	const uint8_t* addr;
	uint8_t type;
	uint16_t size;
	uint16_t blocks;
	size_t pos;
} se3_flash_it;

#define SE3_FLASH_TYPE_SERIAL 1  ///< Device's serial number

////CRYPTO
/** \brief L1 CRYPTO_INIT handler
 *
 *  Initialize a cryptographic context
 *  L1_crypto_init : (algo:ui16, mode:ui16, key_id:ui32) => (sid:ui32)
 */
//uint16_t crypto_init(uint16_t req_size, const uint8_t* req, uint16_t* resp_size, uint8_t* resp);

/** \brief L1 CRYPTO_UPDATE handler
 *
 *  Use a cryptographic context
 *  L1_crypto_update : (
 *      sid:ui32, flags:ui16, datain1-len:ui16, datain2-len:ui16, pad-to-16[6],
 *      datain1[datain1-len], pad-to-16[...], datain2[datain2-len])
 *  => (dataout-len, pad-to-16[14], dataout[dataout-len])
 */
uint16_t crypto_update(uint16_t req_size, const uint8_t* req, uint16_t* resp_size, uint8_t* resp);

/** \brief L1 CRYPTO_SET_TIME handler
 *
 *  Set device time for key validity
 *  crypto_set_time : (devtime:ui32) => ()
 */
uint16_t crypto_set_time(uint16_t req_size, const uint8_t* req, uint16_t* resp_size, uint8_t* resp);

/** \brief L1 CRYPTO_SET_TIME handler
 *
 *  Get list of available algorithms
 *  crypto_list : () => (count:ui16, algoinfo0, algoinfo1, ...)
 *      algoinfo : (name[16], type:u16, block_size:u16, key_size:u16)
 */
uint16_t crypto_list(uint16_t req_size, const uint8_t* req, uint16_t* resp_size, uint8_t* resp);




/*SECUBE FLASH FUNCTIONS*/


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

void se3_security_init();

