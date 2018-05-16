#pragma once

#include "pbkdf2.h"
#include "aes256.h"
#include "crc16.h"
#include "sha256.h"

#include "se3c1def.h"

#include <stdbool.h>

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

////CRYPTO
/** \brief L1 CRYPTO_INIT handler
 *
 *  Initialize a cryptographic context
 *  L1_crypto_init : (algo:ui16, mode:ui16, key_id:ui32) => (sid:ui32)
 */
uint16_t crypto_init(uint16_t req_size, const uint8_t* req, uint16_t* resp_size, uint8_t* resp);

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
