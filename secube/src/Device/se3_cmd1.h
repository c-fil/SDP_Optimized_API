/**
 *  \file se3_cmd1.h
 *  \author Nicola Ferri
 *  \brief L1 command dispatch and execute
 */

#pragma once

#include "se3c1.h"

/** \brief L0 CMD1 command handler
 * 
 *  Execute a L1 command
 */
uint16_t L0d_cmd1(uint16_t req_size, const uint8_t* req, uint16_t* resp_size, uint8_t* resp);