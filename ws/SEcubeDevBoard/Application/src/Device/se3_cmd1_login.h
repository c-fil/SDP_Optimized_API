/**
 *  \file se3_cmd1_login.h
 *  \author Nicola Ferri
 *  \brief L1 handlers for login operations
 */

#pragma once
#include "se3c1.h"
#include "sha256.h"
#include "aes256.h"
#include "pbkdf2.h"

/** \brief L1 CHALLENGE command handler
 *  
 *  Get a login challenge from the device
 */
uint16_t L1d_challenge(uint16_t req_size, const uint8_t* req, uint16_t* resp_size, uint8_t* resp);

/** \brief L1 LOGIN command handler
 *
 *  Respond to challenge and complete the login
 */
uint16_t L1d_login(uint16_t req_size, const uint8_t* req, uint16_t* resp_size, uint8_t* resp);

/** \brief L1 LOGOUT command handler
 *
 *  Log out and release resources
 */
uint16_t L1d_logout(uint16_t req_size, const uint8_t* req, uint16_t* resp_size, uint8_t* resp);




