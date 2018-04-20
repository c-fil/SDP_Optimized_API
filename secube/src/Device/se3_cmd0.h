/**
 *  \file se3_cmd0.h
 *  \author Nicola Ferri
 *  \brief L0 command handlers
 */

#pragma once

#include "se3c0.h"

/** \brief L0 ECHO command handler
 *
 *  Send back received data
 */
uint16_t L0d_echo(uint16_t req_size, const uint8_t* req, uint16_t* resp_size, uint8_t* resp);

/** \brief L0 FACTORY_INIT command handler
 *
 *  Initialize device's serial number
 */
uint16_t L0d_factory_init(uint16_t req_size, const uint8_t* req, uint16_t* resp_size, uint8_t* resp);


/** \brief L0 FACTORY_INIT command handler
 *
 *  Reset USEcube to boot mode
 */
uint16_t L0d_bootmode_reset(uint16_t req_size, const uint8_t* req, uint16_t* resp_size, uint8_t* resp);
