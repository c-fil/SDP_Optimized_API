/*
 * se3_disp_core.h
 *
 *  Created on: 29 apr 2018
 *      Author: Pietro
 */

#include "se3_cmd1.h"

#include "sha256.h"
#include "aes256.h"
#include "se3_algo_Aes.h"
#include "se3_algo_sha256.h"
#include "se3_algo_HmacSha256.h"
#include "se3_algo_AesHmacSha256s.h"
#include "se3_algo_aes256hmacsha256.h"


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


/** algorithm description table */
extern se3_algo_descriptor L1d_algo_table[SE3_ALGO_MAX];

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