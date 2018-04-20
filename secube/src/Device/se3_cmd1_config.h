/**
 *  \file se3_cmd1_config.h
 *  \author Nicola Ferri
 *  \brief L1 handlers for configuration record operations
 */

#pragma once
#include "se3c1.h"

/** \brief L1 CONFIG command handler
 *  
 *  Get or set a configuration record
 */
uint16_t L1d_config(uint16_t req_size, const uint8_t* req, uint16_t* resp_size, uint8_t* resp);

