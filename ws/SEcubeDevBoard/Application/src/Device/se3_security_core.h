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
