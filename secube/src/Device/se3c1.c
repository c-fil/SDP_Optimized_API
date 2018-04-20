/**
 *  \file se3c1.c
 *  \author Nicola Ferri
 *  \brief L1 structures and functions
 */

#include "se3c1.h"
#include "se3_flash.h"
#include "se3_cmd1.h"

uint8_t se3_sessions_buf[SE3_SESSIONS_BUF];
uint8_t* se3_sessions_index[SE3_SESSIONS_MAX];
SE3_L1_GLOBALS se3c1;

#include "se3_algo_Aes.h"
#include "se3_algo_sha256.h"
#include "se3_algo_HmacSha256.h"
#include "se3_algo_AesHmacSha256s.h"
#include "se3_algo_aes256hmacsha256.h"

/* Cryptographic algorithms handlers and display info */
se3_algo_descriptor L1d_algo_table[SE3_ALGO_MAX] = {
	{
		se3_algo_Aes_init,
		se3_algo_Aes_update,
		sizeof(B5_tAesCtx),
		"Aes",
		SE3_CRYPTO_TYPE_BLOCKCIPHER,
		B5_AES_BLK_SIZE,
		B5_AES_256 },
	{
		se3_algo_Sha256_init,
		se3_algo_Sha256_update,
		sizeof(B5_tSha256Ctx),
		"Sha256",
		SE3_CRYPTO_TYPE_DIGEST,
		B5_SHA256_DIGEST_SIZE,
		0 },
	{
		se3_algo_HmacSha256_init,
		se3_algo_HmacSha256_update,
		sizeof(B5_tHmacSha256Ctx),
		"HmacSha256",
		SE3_CRYPTO_TYPE_DIGEST,
		B5_SHA256_DIGEST_SIZE,
		B5_AES_256 },
	{
		se3_algo_AesHmacSha256s_init,
		se3_algo_AesHmacSha256s_update,
		sizeof(B5_tAesCtx) + sizeof(B5_tHmacSha256Ctx) + 2 * B5_AES_256 + sizeof(uint16_t) + 3 * sizeof(uint8_t),
		"AesHmacSha256s",
		SE3_CRYPTO_TYPE_BLOCKCIPHER_AUTH,
		B5_AES_BLK_SIZE,
		B5_AES_256 },
	{
		se3_algo_aes256hmacsha256_init,
		se3_algo_aes256hmacsha256_update,
		sizeof(B5_tAesCtx) + sizeof(B5_tHmacSha256Ctx),
		"AES256HMACSHA256",
		SE3_CRYPTO_TYPE_BLOCKCIPHER_AUTH,
		B5_AES_BLK_SIZE,
		B5_AES_256 },
	{ NULL, NULL, 0, "", 0, 0, 0 },
	{ NULL, NULL, 0, "", 0, 0, 0 },
	{ NULL, NULL, 0, "", 0, 0, 0 }
};

static bool se3c1_record_find(uint16_t record_type, se3_flash_it* it)
{
    uint16_t it_record_type = 0;
    while (se3_flash_it_next(it)) {
        if (it->type == SE3_FLASH_TYPE_RECORD) {
            SE3_GET16(it->addr, SE3_RECORD_OFFSET_TYPE, it_record_type);
            if (it_record_type == record_type) {
                return true;
            }
        }
    }
    return false;
}

bool se3c1_record_set(uint16_t type, const uint8_t* data)
{
    se3_flash_it it;
    bool found = false;
    se3_flash_it it2;
    uint8_t tmp[2];
    if (type >= SE3_RECORD_MAX) {
        return false;
    }
    se3_flash_it_init(&it);
    if (se3c1_record_find(type, &it)) {
        found = true;
    }

    // allocate new flash block
    memcpy(&it2, &it, sizeof(se3_flash_it));
    if (!se3_flash_it_new(&it2, SE3_FLASH_TYPE_RECORD, SE3_RECORD_SIZE_TYPE + SE3_RECORD_SIZE)) {
        return false;
    }
    // write record type and data
    if (!se3_flash_it_write(&it2, SE3_RECORD_OFFSET_DATA, data, SE3_RECORD_SIZE)) {
        return false;
    }
    SE3_SET16(tmp, 0, type);
    if (!se3_flash_it_write(&it2, SE3_RECORD_OFFSET_TYPE, tmp, SE3_RECORD_SIZE_TYPE)) {
        return false;
    }

    if (found) {
        // delete previously found flash block
        if (!se3_flash_it_delete(&it)) {
            return false;
        }
    }

    return true;
}


bool se3c1_record_get(uint16_t type, uint8_t* data)
{
    se3_flash_it it;
    if (type >= SE3_RECORD_MAX) {
        return false;
    }
    se3_flash_it_init(&it);
    if (!se3c1_record_find(type, &it)) {
        return false;
    }
    memcpy(data, it.addr + SE3_RECORD_OFFSET_DATA, SE3_RECORD_SIZE);
    return true;
}

void se3c1_login_cleanup()
{
    size_t i;
    se3_mem_reset(&(se3c1.sessions));
    se3c1.login.y = false;
    se3c1.login.access = 0;
    se3c1.login.challenge_access = SE3_ACCESS_MAX;
    se3c1.login.cryptoctx_initialized = false;
    //memset(se3c1.login.key, 0, SE3_L1_KEY_SIZE);
    memcpy(se3c1.login.key, se3_magic, SE3_L1_KEY_SIZE);
    memset(se3c1.login.token, 0, SE3_L1_TOKEN_SIZE);
    for (i = 0; i < SE3_SESSIONS_MAX; i++) {
        se3c1.sessions_algo[i] = SE3_ALGO_INVALID;
    }

}



void se3c1_init()
{
    memset((void*)&se3c1, 0, sizeof(SE3_L1_GLOBALS));

    se3c1.records[SE3_RECORD_TYPE_USERPIN].read_access = SE3_ACCESS_MAX;
    se3c1.records[SE3_RECORD_TYPE_USERPIN].write_access = SE3_ACCESS_ADMIN;

    se3c1.records[SE3_RECORD_TYPE_ADMINPIN].read_access = SE3_ACCESS_MAX;
    se3c1.records[SE3_RECORD_TYPE_ADMINPIN].write_access = SE3_ACCESS_ADMIN;

    se3_mem_init(
        &(se3c1.sessions),
        SE3_SESSIONS_MAX, se3_sessions_index,
        SE3_SESSIONS_BUF, se3_sessions_buf);

    se3c1_login_cleanup();
}
