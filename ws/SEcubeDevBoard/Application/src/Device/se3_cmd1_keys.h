/**
 *  \file se3_cmd1_keys.h
 *  \author Nicola Ferri
 *  \brief L1 handlers for key management operations
 */

#pragma once
#include "se3c1.h"
#include "sha256.h"
#include "aes256.h"

/** \brief L1 KEY_EDIT
 *
 *  Insert, delete or update a key
 */
uint16_t L1d_key_edit(uint16_t req_size, const uint8_t* req, uint16_t* resp_size, uint8_t* resp);

/** \brief L1 KEY_LIST
 *
 *  Get a list of keys in the device
 */
uint16_t L1d_key_list(uint16_t req_size, const uint8_t* req, uint16_t* resp_size, uint8_t* resp);




