/**
 *  \file se3_cmd.h
 *  \author Nicola Ferri
 *  \brief L0 command dispatch and execute
 */

#pragma once

#include "se3c0.h"

/** \brief Execute received command
 *  
 *  Process the last received request and produce a response
 */
void se3_cmd_execute();
