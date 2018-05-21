#include "se3_disp_core.h"
#include "se3_common.h"



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

void dispatcher_handler (
		int32_t algo,
		const uint8_t *pw,
		size_t npw,
		const uint8_t *salt,
		size_t nsalt,
		uint32_t iterations,
		uint8_t *out, size_t nout){
    switch(algo) {
		case PBKDF2HmacSha256_t:
			PBKDF2HmacSha256( pw, npw, salt, nsalt, iterations, out, nout);
			break;

    	default:
    		break;
    }
}


uint16_t crypto_init(se3_mem *sessions, bool logged, uint32_t key_identificator,  uint16_t modality)
{
	/* E' un comando lanciato dall'host che riceve la request,
	 * riempie le strutture dati adeguate ed esegue la funzione di
	 * init adeguata all'algoritmo richiesto; la struttura di input
	 * contiene una chiave, la cui validità verrà controllata.
	 * La richiesta spacchettata ci darà infos su mode, key e context (algo)
	 * usati come input per l'handler precedentemente scelto.
	 *
	 *
	 * */
//    struct {
//        uint16_t algo;
//        uint16_t mode;
//        uint32_t key_id;
//    } req_params;
//    struct {
//        uint32_t sid;
//    } resp_params;
//
//    se3_flash_key key;
//    se3_flash_it it = { .addr = NULL };
//    se3_crypto_init_handler handler = NULL;
//    uint32_t status;
//    int sid;
//    uint8_t* ctx;
//
//    if (req_size != SE3_CMD1_CRYPTO_INIT_REQ_SIZE) {
//        SE3_TRACE(("[L1d_crypto_init] req size mismatch\n"));
//        return SE3_ERR_PARAMS;
//    }
//
//    if (!login.y) {
//        SE3_TRACE(("[L1d_crypto_init] not logged in\n"));
//        return SE3_ERR_ACCESS;
//    }
//
//   // SE3_GET16(req, SE3_CMD1_CRYPTO_INIT_REQ_OFF_ALGO, req_params.algo);
//   // SE3_GET16(req, SE3_CMD1_CRYPTO_INIT_REQ_OFF_MODE, req_params.mode);
//    //SE3_GET32(req, SE3_CMD1_CRYPTO_INIT_REQ_OFF_KEY_ID, req_params.key_id);
//   //////////////////// || \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
//    /////////////////// || \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
//  ////////////////////  \/ \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
//
//	if(!se_key_work(&req_params.algo,modality, key_identificator))
//		return SE3_ERR_PARAMS;
//  /////////////////////////////////////////////////////////////////////
//
//	if (req_params.algo < SE3_ALGO_MAX) {
//        handler = L1d_algo_table[req_params.algo].init;
//    }
//    if (handler == NULL) {
//        SE3_TRACE(("[L1d_crypto_init] algo not found\n"));
//        return SE3_ERR_PARAMS;
//    }
//
//
//
//
//    // use request buffer to temporarily store key data
//    // !! modifying request buffer
//    key.data = (uint8_t*)req + 16;
//    key.name = NULL;
//    key.id = req_params.key_id;
//
//    if (key.id == SE3_KEY_INVALID) {
//        memset(key.data, 0, SE3_KEY_DATA_MAX);
//    }
//    else {
//        se3_flash_it_init(&it);
//        if (!se3_key_find(key.id, &it)) {
//            it.addr = NULL;
//        }
//        if (NULL == it.addr) {
//            SE3_TRACE(("[L1d_crypto_init] key not found\n"));
//            return SE3_ERR_RESOURCE;
//        }
//        se3_key_read(&it, &key);
//
//		if (key.validity < time_get() || !now_initialized_get()) {
//			SE3_TRACE(("[L1d_crypto_init] key expired\n"));
//			return SE3_ERR_EXPIRED;
//		}
//    }
//
//    resp_params.sid = SE3_SESSION_INVALID;
//    sid = se3_mem_alloc(&(sessions), L1d_algo_table[req_params.algo].size);
//    if (sid >= 0) {
//        resp_params.sid = (uint32_t)sid;
//    }
//
//    if (resp_params.sid == SE3_SESSION_INVALID) {
//        SE3_TRACE(("[L1d_crypto_init] cannot allocate session\n"));
//        return SE3_ERR_MEMORY;
//    }
//
//    ctx = se3_mem_ptr(&(sessions), sid);
//    if (ctx == NULL) {
//        // this should not happen
//        SE3_TRACE(("[L1d_crypto_init] NULL session pointer\n"));
//        return SE3_ERR_HW;
//    }
//
//    status = handler(&key, req_params.mode, ctx);
//
//    if (SE3_OK != status) {
//        // free the allocated session
//        se3_mem_free(&(sessions), (int32_t)resp_params.sid);
//
//        SE3_TRACE(("[L1d_crypto_init] crypto handler failed\n"));
//        return status;
//    }
//
//    // link session to algo
//    sessions_algo[resp_params.sid] = req_params.algo;
//
//
//    SE3_SET32(resp, SE3_CMD1_CRYPTO_INIT_RESP_OFF_SID, resp_params.sid);
//
//    *resp_size = SE3_CMD1_CRYPTO_INIT_RESP_SIZE;

	return SE3_OK;
}

void se3_dispatcher_init(SE3_SERIAL* serial_disp){

	se3_security_init(serial_disp);
}

/*
 * Type stands for user access [0 admin 1 user]
 * TODO: no sense
 */
bool record_get(uint16_t type, uint8_t* data)
{
    se3_flash_it it;
    if (type >= SE3_RECORD_MAX) {
        return false;
    }
    se3_flash_it_init(&it);
    if (!record_find(type, &it)) {
        return false;
    }
    memcpy(data, it.addr + SE3_RECORD_OFFSET_DATA, SE3_RECORD_SIZE);
    return true;
}

bool record_set(uint16_t type, const uint8_t* data)
{
    se3_flash_it it;
    bool found = false;
    se3_flash_it it2;
    uint8_t tmp[2];
    if (type >= SE3_RECORD_MAX) {
        return false;
    }
    se3_flash_it_init(&it);
    if (record_find(type, &it)) {
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

bool record_find(uint16_t record_type, se3_flash_it* it)
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



