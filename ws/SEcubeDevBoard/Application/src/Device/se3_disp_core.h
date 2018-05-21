#pragma once
#include <string.h>

#include "se3_security_core.h"
//#include "se3_fpga_core.h"    //TODO: FPGA core to be implemented
//#include "se3_smartcard.h"	//TODO: SMARTCARD core to be implemented

#include "se3_algo_Aes.h"
#include "se3_algo_sha256.h"
#include "se3_algo_HmacSha256.h"
#include "se3_algo_AesHmacSha256s.h"
#include "se3_algo_aes256hmacsha256.h"
#include "se3_memory.h"

// ---- records ----

#define SE3_FLASH_TYPE_RECORD 0xF0  ///< flash node type: record


/** \brief Record information */
#define SE3_RECORD_SIZE_TYPE 2  ///< record.type field size
#define SE3_RECORD_OFFSET_TYPE 0 ///< record.type field offset
#define SE3_RECORD_OFFSET_DATA 2 ///< record.data field offset

//HANDLER STRANI
/** \brief L1_crypto_init function type */
typedef uint16_t(*se3_crypto_init_handler)(
	se3_flash_key* key, uint16_t mode, uint8_t* ctx);

/** \brief L1_crypto_update function type */
typedef uint16_t(*se3_crypto_update_handler)(
	uint8_t* ctx, uint16_t flags,
	uint16_t datain1_len, const uint8_t* datain1,
	uint16_t datain2_len, const uint8_t* datain2,
	uint16_t* dataout_len, uint8_t* dataout);

/** \brief algorithm descriptor type */
typedef struct se3_algo_descriptor_ {
	se3_crypto_init_handler init;  ///< L1_crypto_init function
	se3_crypto_update_handler update;  ///< L1_crypto_update function
	uint16_t size;  ///< context size size
	char display_name[16];  ///< name for the algorithm list API
	uint16_t display_type;  ///< type for the algorithm list API
	uint16_t display_block_size;  ///< block size for the algorithm list API
	uint16_t display_key_size;  ///< key size for the algorithm list API
} se3_algo_descriptor;

/** Security algo */

#define	PBKDF2HmacSha256_t 0



/** algorithm description table */
extern se3_algo_descriptor L1d_algo_table[SE3_ALGO_MAX];



/** \brief Flash key structure
 *
 *  Disposition of the fields within the flash node:
 *  0:3     id
 *  4:7     validity
 *  8:9     data_size
 *  10:11   name_size
 *  12:(12+data_size-1)
 *          data
 *  (12+data_size):(12+data_size+name_size-1)
 *          name
 */
//typedef struct se3_flash_key_ {
//	uint32_t id;
//	uint32_t validity;
//	uint16_t data_size;
//	uint16_t name_size;
//	uint8_t* data;
//	uint8_t* name;
//} se3_flash_key;




void dispatcher_handler(
		int32_t algo,
		const uint8_t *pw, size_t npw,
		const uint8_t *salt, size_t nsalt,
		uint32_t iterations,
		uint8_t *out, size_t nout);



void se3_dispatcher_init(SE3_SERIAL* serial_disp);

bool record_set(uint16_t type, const uint8_t* data);

bool record_get(uint16_t type, uint8_t* data);

bool record_find(uint16_t record_type, se3_flash_it* it);
