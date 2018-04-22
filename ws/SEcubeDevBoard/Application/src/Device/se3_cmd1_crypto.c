/**
 *  \file se3_cmd1_crypto.c
 *  \author Nicola Ferri
 *  \brief L1 handlers for crypto operations
 */

#include "se3_cmd1_crypto.h"


/** \brief initialize a crypto context
 *  
 *  L1_crypto_init : (algo:ui16, mode:ui16, key_id:ui32) => (sid:ui32)
 */
uint16_t L1d_crypto_init(uint16_t req_size, const uint8_t* req, uint16_t* resp_size, uint8_t* resp)
{
    struct {
        uint16_t algo;
        uint16_t mode;
        uint32_t key_id;
    } req_params;
    struct {
        uint32_t sid;
    } resp_params;
    
    se3_flash_key key;
    se3_flash_it it = { .addr = NULL };
    se3_crypto_init_handler handler = NULL;
    uint32_t status;
    int sid;
    uint8_t* ctx;

    if (req_size != SE3_CMD1_CRYPTO_INIT_REQ_SIZE) {
        SE3_TRACE(("[L1d_crypto_init] req size mismatch\n"));
        return SE3_ERR_PARAMS;
    }

    if (!se3c1.login.y) {
        SE3_TRACE(("[L1d_crypto_init] not logged in\n"));
        return SE3_ERR_ACCESS;
    }

    SE3_GET16(req, SE3_CMD1_CRYPTO_INIT_REQ_OFF_ALGO, req_params.algo);
    SE3_GET16(req, SE3_CMD1_CRYPTO_INIT_REQ_OFF_MODE, req_params.mode);
    SE3_GET32(req, SE3_CMD1_CRYPTO_INIT_REQ_OFF_KEY_ID, req_params.key_id);

    if (req_params.algo < SE3_ALGO_MAX) {
        handler = L1d_algo_table[req_params.algo].init;
    }
    if (handler == NULL) {
        SE3_TRACE(("[L1d_crypto_init] algo not found\n"));
        return SE3_ERR_PARAMS;
    }

    // use request buffer to temporarily store key data
    // !! modifying request buffer
    key.data = (uint8_t*)req + 16;
    key.name = NULL;
    key.id = req_params.key_id;

    if (key.id == SE3_KEY_INVALID) {
        memset(key.data, 0, SE3_KEY_DATA_MAX);
    }
    else {
        se3_flash_it_init(&it);
        if (!se3_key_find(key.id, &it)) {
            it.addr = NULL;
        }
        if (NULL == it.addr) {
            SE3_TRACE(("[L1d_crypto_init] key not found\n"));
            return SE3_ERR_RESOURCE;
        }
        se3_key_read(&it, &key);

		if (key.validity < se3c0_time_get() || !se3c0.now_initialized) {
			SE3_TRACE(("[L1d_crypto_init] key expired\n"));
			return SE3_ERR_EXPIRED;
		}
    }
    
    resp_params.sid = SE3_SESSION_INVALID;
    sid = se3_mem_alloc(&(se3c1.sessions), L1d_algo_table[req_params.algo].size);
    if (sid >= 0) {
        resp_params.sid = (uint32_t)sid;
    }

    if (resp_params.sid == SE3_SESSION_INVALID) {
        SE3_TRACE(("[L1d_crypto_init] cannot allocate session\n"));
        return SE3_ERR_MEMORY;
    }
    
    ctx = se3_mem_ptr(&(se3c1.sessions), sid);
    if (ctx == NULL) {
        // this should not happen
        SE3_TRACE(("[L1d_crypto_init] NULL session pointer\n"));
        return SE3_ERR_HW;
    }
    
    status = handler(&key, req_params.mode, ctx);

    if (SE3_OK != status) {
        // free the allocated session
        se3_mem_free(&(se3c1.sessions), (int32_t)resp_params.sid);

        SE3_TRACE(("[L1d_crypto_init] crypto handler failed\n"));
        return status;
    }

    // link session to algo
    se3c1.sessions_algo[resp_params.sid] = req_params.algo;
    
    SE3_SET32(resp, SE3_CMD1_CRYPTO_INIT_RESP_OFF_SID, resp_params.sid);

    *resp_size = SE3_CMD1_CRYPTO_INIT_RESP_SIZE;

	return SE3_OK;
}


/** \brief use a crypto context
 *  
 *  L1_crypto_update : (
 *      sid:ui32, flags:ui16, datain1-len:ui16, datain2-len:ui16, pad-to-16[6], 
 *      datain1[datain1-len], pad-to-16[...], datain2[datain2-len])
 *  => (dataout-len, pad-to-16[14], dataout[dataout-len])
 */
uint16_t L1d_crypto_update(uint16_t req_size, const uint8_t* req, uint16_t* resp_size, uint8_t* resp)
{
    struct {
        uint32_t sid;
        uint16_t flags;
        uint16_t datain1_len;
        uint16_t datain2_len;
        const uint8_t* datain1;
        const uint8_t* datain2;
    } req_params;
    struct {
        uint16_t dataout_len;
        uint8_t* dataout;
    } resp_params;
    uint16_t datain1_len_padded;
    se3_crypto_update_handler handler = NULL;
    uint16_t algo;
    uint8_t* ctx;
    uint16_t status;

    if (req_size < SE3_CMD1_CRYPTO_UPDATE_REQ_OFF_DATA) {
        SE3_TRACE(("[L1d_crypto_update] req size mismatch\n"));
        return SE3_ERR_PARAMS;
    }

    if (!se3c1.login.y) {
        SE3_TRACE(("[L1d_crypto_update] not logged in\n"));
        return SE3_ERR_ACCESS;
    }

    SE3_GET32(req, SE3_CMD1_CRYPTO_UPDATE_REQ_OFF_SID, req_params.sid);
    SE3_GET16(req, SE3_CMD1_CRYPTO_UPDATE_REQ_OFF_FLAGS, req_params.flags);
    SE3_GET16(req, SE3_CMD1_CRYPTO_UPDATE_REQ_OFF_DATAIN1_LEN, req_params.datain1_len);
    SE3_GET16(req, SE3_CMD1_CRYPTO_UPDATE_REQ_OFF_DATAIN2_LEN, req_params.datain2_len);
    req_params.datain1 = req + SE3_CMD1_CRYPTO_UPDATE_REQ_OFF_DATA;
    if (req_params.datain1_len % 16) {
        datain1_len_padded = req_params.datain1_len + (16 - (req_params.datain1_len % 16));
    }
    else {
        datain1_len_padded = req_params.datain1_len;
    }
    req_params.datain2 = req + SE3_CMD1_CRYPTO_UPDATE_REQ_OFF_DATA + datain1_len_padded;
    
    if (SE3_CMD1_CRYPTO_UPDATE_REQ_OFF_DATA + datain1_len_padded + req_params.datain2_len > SE3_REQ1_MAX_DATA) {
        SE3_TRACE(("[L1d_crypto_update] data size exceeds packet limit\n"));
        return SE3_ERR_PARAMS;
    }

    if (req_params.sid >= SE3_SESSIONS_MAX) {
        SE3_TRACE(("[L1d_crypto_update] invalid sid\n"));
        return SE3_ERR_RESOURCE;
    }

    algo = se3c1.sessions_algo[req_params.sid];
    if (algo >= SE3_ALGO_MAX) {
        SE3_TRACE(("[L1d_crypto_update] invalid algo for this sid (wrong sid?)\n"));
        return SE3_ERR_RESOURCE;
    }

    handler = L1d_algo_table[algo].update;
    if (handler == NULL) {
        SE3_TRACE(("[L1d_crypto_update] invalid crypto handler for this algo (wrong sid?)\n"));
        return SE3_ERR_RESOURCE;
    }

    ctx = se3_mem_ptr(&(se3c1.sessions), (int32_t)req_params.sid);
    if (ctx == NULL) {
        SE3_TRACE(("[L1d_crypto_update] session not found\n"));
        return SE3_ERR_RESOURCE;
    }

    resp_params.dataout_len = 0;
    resp_params.dataout = resp + SE3_CMD1_CRYPTO_UPDATE_RESP_OFF_DATA;

    status = handler(
        ctx, req_params.flags,
        req_params.datain1_len, req_params.datain1,
        req_params.datain2_len, req_params.datain2,
        &(resp_params.dataout_len), resp_params.dataout);

    if (SE3_OK != status) {
        SE3_TRACE(("[L1d_crypto_update] crypto handler failed\n"));
        return status;
    }

    if (req_params.flags & SE3_CRYPTO_FLAG_FINIT) {
        se3_mem_free(&(se3c1.sessions), (int32_t)req_params.sid);
    }

    SE3_SET16(resp, SE3_CMD1_CRYPTO_UPDATE_RESP_OFF_DATAOUT_LEN, resp_params.dataout_len);
    *resp_size = SE3_CMD1_CRYPTO_UPDATE_RESP_OFF_DATA + resp_params.dataout_len;

    return SE3_OK;
}


/** \brief set device time for key validity
 *  
 *  crypto_set_time : (devtime:ui32) => ()
 */
uint16_t L1d_crypto_set_time(uint16_t req_size, const uint8_t* req, uint16_t* resp_size, uint8_t* resp)
{
    struct {
        uint32_t devtime;
    } req_params;

    if (req_size != SE3_CMD1_CRYPTO_SET_TIME_REQ_SIZE) {
        SE3_TRACE(("[L1d_crypto_set_time] req size mismatch\n"));
        return SE3_ERR_PARAMS;
    }
    if (!se3c1.login.y) {
        SE3_TRACE(("[L1d_crypto_set_time] not logged in\n"));
        return SE3_ERR_ACCESS;
    }

    SE3_GET32(req, SE3_CMD1_CRYPTO_SET_TIME_REQ_OFF_DEVTIME, req_params.devtime);
    
    se3c0_time_set((uint64_t)req_params.devtime);

    return SE3_OK;
}

/** \brief get list of available algorithms
 *
 *  crypto_list : () => (count:ui16, algoinfo0, algoinfo1, ...)
 *      algoinfo : (name[16], type:u16, block_size:u16, key_size:u16)
 */
uint16_t L1d_crypto_list(uint16_t req_size, const uint8_t* req, uint16_t* resp_size, uint8_t* resp)
{
    struct {
        uint16_t count;
        uint8_t* algoinfo;
    } resp_params;
    uint8_t* p;
    size_t i;
    uint16_t size;

    if (req_size != SE3_CMD1_CRYPTO_LIST_REQ_SIZE) {
        SE3_TRACE(("[L1d_crypto_list] req size mismatch\n"));
        return SE3_ERR_PARAMS;
    }
    if (!se3c1.login.y) {
        SE3_TRACE(("[L1d_crypto_list] not logged in\n"));
        return SE3_ERR_ACCESS;
    }

    resp_params.algoinfo = resp + SE3_CMD1_CRYPTO_LIST_RESP_OFF_ALGOINFO;

    size = SE3_CMD1_CRYPTO_LIST_RESP_OFF_ALGOINFO;
    resp_params.count = 0;
    p = resp_params.algoinfo;
    for (i = 0; i < SE3_ALGO_MAX; i++) {
        if ((L1d_algo_table[i].init != NULL) && (L1d_algo_table[i].update != NULL)) {
            memcpy(p + SE3_CMD1_CRYPTO_ALGOINFO_OFF_NAME, L1d_algo_table[i].display_name, SE3_CMD1_CRYPTO_ALGOINFO_NAME_SIZE);
            SE3_SET16(p, SE3_CMD1_CRYPTO_ALGOINFO_OFF_TYPE, L1d_algo_table[i].display_type);
            SE3_SET16(p, SE3_CMD1_CRYPTO_ALGOINFO_OFF_BLOCK_SIZE, L1d_algo_table[i].display_block_size);
            SE3_SET16(p, SE3_CMD1_CRYPTO_ALGOINFO_OFF_KEY_SIZE, L1d_algo_table[i].display_key_size);

            (resp_params.count)++;
            size += SE3_CMD1_CRYPTO_ALGOINFO_SIZE;
            p += SE3_CMD1_CRYPTO_ALGOINFO_SIZE;
        }
    }
    SE3_SET16(resp, SE3_CMD1_CRYPTO_LIST_RESP_OFF_COUNT, resp_params.count);
    *resp_size = size;
    return SE3_OK;
}
