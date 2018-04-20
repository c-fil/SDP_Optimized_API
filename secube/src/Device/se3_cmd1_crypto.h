/**
 *  \file se3_cmd1_crypto.h
 *  \author Nicola Ferri
 *  \brief L1 handlers for crypto operations
 */

#pragma once
#include "se3c1.h"
#include "se3_keys.h"

/** \brief L1 CRYPTO_INIT handler
 *  
 *  Initialize a cryptographic context
 */
uint16_t L1d_crypto_init(uint16_t req_size, const uint8_t* req, uint16_t* resp_size, uint8_t* resp);

/** \brief L1 CRYPTO_UPDATE handler
 *
 *  Use a cryptographic context
 */
uint16_t L1d_crypto_update(uint16_t req_size, const uint8_t* req, uint16_t* resp_size, uint8_t* resp);

/** \brief L1 CRYPTO_SET_TIME handler
 *
 *  Set device time for key validity
 */
uint16_t L1d_crypto_set_time(uint16_t req_size, const uint8_t* req, uint16_t* resp_size, uint8_t* resp);

/** \brief L1 CRYPTO_SET_TIME handler
 *
 *  Get list of available algorithms
 */
uint16_t L1d_crypto_list(uint16_t req_size, const uint8_t* req, uint16_t* resp_size, uint8_t* resp);


