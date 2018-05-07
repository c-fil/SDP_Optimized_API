
#pragma once

#ifndef CUBESIM
#include "stm32f4xx.h"
#include "stm32f4xx_hal.h"
#define SE3_FLASH_S0  (FLASH_SECTOR_10)
#define SE3_FLASH_S1  (FLASH_SECTOR_11)
#define SE3_FLASH_S0_ADDR  ((uint32_t)0x080C0000)
#define SE3_FLASH_S1_ADDR  ((uint32_t)0x080E0000)
#define SE3_FLASH_SECTOR_SIZE (128*1024)
#endif

#include "stdbool.h"

/*
Structure of flash:
	0:31          magic
	32:2047       index
	2048:131071   data

	The data section is divided into 2016 64-byte blocks.
	Each byte of the index stores the type of the corresponding data block.
	A special value (SE3_FLASH_TYPE_CONT) indicates that the block is the continuation of the 
	previous one.
	if the block is invalid, its type is 0. If it has not been written yet, the type is 0xFF.
*/


/** \brief Flash management structure */
typedef struct SE3_FLASH_INFO_ {
    uint32_t sector;  ///< active sector number
    const uint8_t* base;
    const uint8_t* index;
    const uint8_t* data;
    size_t first_free_pos;
    size_t used;
    size_t allocated;
} SE3_FLASH_INFO;

/** \brief Flash node iterator structure */
typedef struct se3_flash_it_ {
	const uint8_t* addr;
	uint8_t type;
	uint16_t size;
	uint16_t blocks;
	size_t pos;
} se3_flash_it;

/** Flash nodes' default and reserved types */
enum {
	SE3_FLASH_TYPE_INVALID = 0,  ///< Invalid node
	SE3_FLASH_TYPE_SERIAL = 1,  ///< Device's serial number
	SE3_FLASH_TYPE_CONT = 0xFE,  ///< Continuation of previous node
	SE3_FLASH_TYPE_EMPTY = 0xFF  ///< Not written yet
};

/** Flash fields sizes */
enum {
	SE3_FLASH_MAGIC_SIZE = 32,
	SE3_FLASH_INDEX_SIZE = 2016,
	SE3_FLASH_BLOCK_SIZE = 64,
	SE3_FLASH_NODE_MAX = (4 * 1024),
	SE3_FLASH_NODE_DATA_MAX = (SE3_FLASH_NODE_MAX - 2)
};






