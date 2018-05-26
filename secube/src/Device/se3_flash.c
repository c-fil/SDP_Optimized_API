
#include "se3_flash.h"


bool flash_fill(uint32_t addr, uint8_t val, size_t size)
{
	HAL_FLASH_Unlock();
	while (size) {
		if (HAL_OK != HAL_FLASH_Program(FLASH_TYPEPROGRAM_BYTE, addr, (uint64_t)val)) {
			HAL_FLASH_Lock();
			return false;
		}
		size--;
		addr++;
	}
	HAL_FLASH_Lock();
	return true;
}

bool flash_zero(uint32_t addr, size_t size)
{
	HAL_FLASH_Unlock();
	while (size) {
		if (HAL_OK != HAL_FLASH_Program(FLASH_TYPEPROGRAM_BYTE, addr, 0)) {
			HAL_FLASH_Lock();
			return false;
		}
		size--;
		addr++;
	}
	HAL_FLASH_Lock();
	return true;
}

bool flash_program(uint32_t addr, const uint8_t* data, size_t size)
{
	HAL_FLASH_Unlock();
	while (size) {
		if (HAL_OK != HAL_FLASH_Program(FLASH_TYPEPROGRAM_BYTE, addr, (uint64_t)*data)) {
			HAL_FLASH_Lock();
			return false;
		}
		size--;
		addr++;
		data++;
	}
	HAL_FLASH_Lock();
	return true;
}


bool flash_erase(uint32_t sector) {
#ifdef CUBESIM
    memset((sector == SE3_FLASH_S0) ? (uint8_t*)(SE3_FLASH_S0_ADDR) : (uint8_t*)(SE3_FLASH_S1_ADDR), 0xFF, SE3_FLASH_SECTOR_SIZE);
#else
	FLASH_EraseInitTypeDef EraseInitStruct;
	uint32_t SectorError;
	HAL_StatusTypeDef result;
	
	HAL_FLASH_Unlock();

	EraseInitStruct.TypeErase = FLASH_TYPEERASE_SECTORS;
	EraseInitStruct.VoltageRange = FLASH_VOLTAGE_RANGE_3;
	EraseInitStruct.Sector = sector;
	EraseInitStruct.NbSectors = 1;
	result = HAL_FLASHEx_Erase(&EraseInitStruct, (uint32_t*)&SectorError);
	if (result != HAL_OK){
		HAL_FLASH_Lock();
		return false;
    }
	HAL_FLASH_Lock();
#endif
    return true;
}
