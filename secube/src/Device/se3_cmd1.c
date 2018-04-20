/**
 *  \file se3_cmd1.c
 *  \author Nicola Ferri
 *  \brief L1 command dispatch and execute
 */

#include "se3_cmd1.h"
#include "se3_cmd1_login.h"
#include "se3_cmd1_config.h"
#include "se3_cmd1_keys.h"
#include "se3_cmd1_crypto.h"
#ifndef CUBESIM
#include "se3_rand.h"
#endif

#define SE3_CMD1_MAX (16)

static se3_cmd_func L1d_handlers[SE3_CMD1_MAX] = {
    /* 0  */ NULL,
    /* 1  */ L1d_challenge,
    /* 2  */ L1d_login,
    /* 3  */ L1d_logout,
    /* 4  */ L1d_config,
    /* 5  */ L1d_key_edit,
    /* 6  */ L1d_key_list,
    /* 7  */ L1d_crypto_init,
    /* 8  */ L1d_crypto_update,
    /* 9  */ L1d_crypto_list,
    /* 10 */ L1d_crypto_set_time,
    /* 11 */ NULL,
    /* 12 */ NULL,
    /* 13 */ NULL,
    /* 14 */ NULL,
    /* 15 */ NULL
};

static uint16_t L1d_error(uint16_t req_size, const uint8_t* req, uint16_t* resp_size, uint8_t* resp)
{
    return SE3_ERR_CMD;
}

/** \brief L0 command which executes an L1 command
 *  
 *  This handler also manages encryption and login token check
 */
uint16_t L0d_cmd1(uint16_t req_size, const uint8_t* req, uint16_t* resp_size, uint8_t* resp)
{
    se3_cmd_func handler = NULL;
    uint16_t resp1_size, req1_size;
    uint16_t resp1_size_padded;
    const uint8_t* req1;
    uint8_t* resp1;
    uint16_t status;
    struct {
        const uint8_t* auth;
        const uint8_t* iv;
        const uint8_t* token;
        uint16_t len;
        uint16_t cmd;
        const uint8_t* data;
    } req_params;
    struct {
        uint8_t* auth;
        uint8_t* iv;
        uint8_t* token;
        uint16_t len;
        uint16_t status;
        uint8_t* data;
    } resp_params;

    req_params.auth = req + SE3_REQ1_OFFSET_AUTH;
    req_params.iv = req + SE3_REQ1_OFFSET_IV;
    req_params.token = req + SE3_REQ1_OFFSET_TOKEN;
    req_params.data = req + SE3_REQ1_OFFSET_DATA;

    if (req_size < SE3_REQ1_OFFSET_DATA) {
        SE3_TRACE(("[L0d_cmd1] insufficient req size\n"));
        return SE3_ERR_COMM;
    }

    // prepare request
    if (!se3c1.login.cryptoctx_initialized) {
        se3_payload_cryptoinit(&(se3c1.login.cryptoctx), se3c1.login.key);
        se3c1.login.cryptoctx_initialized = true;
    }
    if (!se3_payload_decrypt(
        &(se3c1.login.cryptoctx), req_params.auth, req_params.iv, 
        /* !! modifying request */ (uint8_t*)(req  + SE3_L1_AUTH_SIZE + SE3_L1_IV_SIZE),
        (req_size - SE3_L1_AUTH_SIZE - SE3_L1_IV_SIZE) / SE3_L1_CRYPTOBLOCK_SIZE, se3c0.req_hdr.cmd_flags))
    {
        SE3_TRACE(("[L0d_cmd1] AUTH failed\n"));
        return SE3_ERR_COMM;
    }
    
    if (se3c1.login.y) {
        if (memcmp(se3c1.login.token, req_params.token, SE3_L1_TOKEN_SIZE)) {
            SE3_TRACE(("[L0d_cmd1] login token mismatch\n"));
            return SE3_ERR_ACCESS;
        }
    }

    SE3_GET16(req, SE3_REQ1_OFFSET_LEN, req_params.len);
    SE3_GET16(req, SE3_REQ1_OFFSET_CMD, req_params.cmd);
    if (req_params.cmd < SE3_CMD1_MAX) {
        handler = L1d_handlers[req_params.cmd];
    }
    if (handler == NULL) {
        handler = L1d_error;
    }

    req1 = req_params.data;
    req1_size = req_params.len;
    resp1 = resp + SE3_RESP1_OFFSET_DATA;
    resp1_size = 0;

    status = handler(req1_size, req1, &resp1_size, resp1);

    resp_params.len = resp1_size;
    resp_params.auth = resp + SE3_RESP1_OFFSET_AUTH;
    resp_params.iv = resp + SE3_RESP1_OFFSET_IV;
    resp_params.token = resp + SE3_RESP1_OFFSET_TOKEN;
    resp_params.status = status;
    resp_params.data = resp1;

    resp1_size_padded = resp1_size;
    if (resp1_size_padded % SE3_L1_CRYPTOBLOCK_SIZE != 0) {
        memset(resp1 + resp1_size_padded, 0, (SE3_L1_CRYPTOBLOCK_SIZE - (resp1_size_padded % SE3_L1_CRYPTOBLOCK_SIZE)));
        resp1_size_padded += (SE3_L1_CRYPTOBLOCK_SIZE - (resp1_size_padded % SE3_L1_CRYPTOBLOCK_SIZE));
    }
    
    *resp_size = SE3_RESP1_OFFSET_DATA + resp1_size_padded;

    // prepare response
    SE3_SET16(resp, SE3_RESP1_OFFSET_LEN, resp_params.len);
    SE3_SET16(resp, SE3_RESP1_OFFSET_STATUS, resp_params.status);
    if (se3c1.login.y) {
        memcpy(resp + SE3_RESP1_OFFSET_TOKEN, se3c1.login.token, SE3_L1_TOKEN_SIZE);
    }
    else {
        memset(resp + SE3_RESP1_OFFSET_TOKEN, 0, SE3_L1_TOKEN_SIZE);
    }
	if (se3c0.req_hdr.cmd_flags & SE3_CMDFLAG_ENCRYPT) {
		se3_rand(SE3_L1_IV_SIZE, resp_params.iv);
	}
	else {
		memset(resp_params.iv, 0, SE3_L1_IV_SIZE);
	}
    se3_payload_encrypt(
        &(se3c1.login.cryptoctx), resp_params.auth, resp_params.iv,
        resp + SE3_L1_AUTH_SIZE + SE3_L1_IV_SIZE, (*resp_size - SE3_L1_AUTH_SIZE - SE3_L1_IV_SIZE) / SE3_L1_CRYPTOBLOCK_SIZE, se3c0.req_hdr.cmd_flags);
    


    return SE3_OK;
}


