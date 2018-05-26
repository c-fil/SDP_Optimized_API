#include "se3_core.h"
#include "se3c0def.h"
#include "se3_rand.h"
////
//L0
SE3_COMM_STATUS comm;
req_header req_hdr;
resp_header resp_hdr;




////



static se3_cmd_func cmd_handlers[SE3_CMD_MAX] = {
    /* 0  */ NULL,
    /* 1  */ challenge,
    /* 2  */ cmd_login,
    /* 3  */ logout,
    /* 4  */ config,
    /* 5  */ key_edit,
    /* 6  */ key_list,
    /* 7  */ NULL, //crypto_init,
    /* 8  */ crypto_update,
    /* 9  */ crypto_list,
    /* 10 */ crypto_set_time,
    /* 11 */ echo,
    /* 12 */ bootmode_reset,
    /* 13 */ factory_init,
    /* 14 */ sec_cmd,
    /* 15 */ cmd_error
};

////
//L1
////
SE3_LOGIN_STATUS login;
se3_mem sessions;
SE3_RECORD_INFO records[SE3_RECORD_MAX];

uint16_t sessions_algo[SE3_SESSIONS_MAX]; //TODO: SDP: Dynamically allocate sessions

//uint8_t se3_comm_request_buffer[SE3_COMM_N*SE3_COMM_BLOCK];
//uint8_t se3_comm_response_buffer[SE3_COMM_N*SE3_COMM_BLOCK];




uint8_t se3_sessions_buf[SE3_SESSIONS_BUF];
uint8_t* se3_sessions_index[SE3_SESSIONS_MAX];


void se3_core_start(){

	while(1){
		//wait for new request/command and execute it
		while(!comm.req_ready);

		comm.resp_ready = false;
		se3_cmd_execute();
		comm.req_ready = false;
		comm.resp_ready = true;
	}

}


void core_init()
{
    /*
     * L0 INIT
     */

    time_init();

	/* COMMUNICATION CORE INITIALIZATION*/

    memset(&serial,0,sizeof(SE3_SERIAL));
    memset(&req_hdr,0,sizeof(req_header));
    memset(&resp_hdr,0,sizeof(resp_header));
    se3_communication_init(&req_hdr, &resp_hdr);
	se3_dispatcher_init();




    /*
     * L1 INIT
     */
    memset((void*)&login, 0, sizeof(SE3_LOGIN_STATUS));
    memset((void*)&records, 0, sizeof(SE3_RECORD_INFO));
    memset((void*)&sessions, 0, sizeof(se3_mem));
    memset((void*)&sessions_algo, 0, SE3_SESSIONS_MAX*sizeof(uint16_t));

    records[SE3_RECORD_TYPE_USERPIN].read_access = SE3_ACCESS_MAX;
    records[SE3_RECORD_TYPE_USERPIN].write_access = SE3_ACCESS_ADMIN;

    records[SE3_RECORD_TYPE_ADMINPIN].read_access = SE3_ACCESS_MAX;
    records[SE3_RECORD_TYPE_ADMINPIN].write_access = SE3_ACCESS_ADMIN;

    se3_mem_init(
        &(sessions),
        SE3_SESSIONS_MAX, se3_sessions_index,
        SE3_SESSIONS_BUF, se3_sessions_buf);

    login_cleanup();
}

void login_cleanup()
{
    size_t i;
    se3_mem_reset(&(sessions));
    login.y = false;
    login.access = 0;
    login.challenge_access = SE3_ACCESS_MAX;
    login.cryptoctx_initialized = false;
    //memset(se3c1.login.key, 0, SE3_L1_KEY_SIZE);
    memcpy(login.key, se3_magic, SE3_L1_KEY_SIZE);
    memset(login.token, 0, SE3_L1_TOKEN_SIZE);
    for (i = 0; i < SE3_SESSIONS_MAX; i++) {
        sessions_algo[i] = SE3_ALGO_INVALID;
    }
}

void se3_cmd_execute()
{
    uint16_t req_blocks = 1, resp_blocks = 1;
    size_t i;
    se3_cmd_func handler = NULL;
	uint32_t cmdtok0;

    req_blocks = req_hdr.len / SE3_COMM_BLOCK;
    if (req_hdr.len % SE3_COMM_BLOCK != 0) {
        req_blocks++;
    }
    if (req_blocks > SE3_COMM_N - 1) {
        // should not happen anyway
        resp_blocks = 0;
        comm.resp_bmap = SE3_BMAP_MAKE(resp_blocks);
        return;
    }
    for (i = 1; i < req_blocks; i++) {
        if (req_hdr.cmdtok[i] != req_hdr.cmdtok[i - 1] + 1) {
            resp_blocks = 0;
            comm.resp_bmap = SE3_BMAP_MAKE(resp_blocks);
            return;
        }
    }

	if (handler == NULL) {
		switch (req_hdr.cmd) {
		case SE3_CMD_MIX:
			handler = cmd_handlers[14];
			break;
		case SE3_CMD_ECHO:
			handler = cmd_handlers[11];
			break;
		case SE3_CMD_FACTORY_INIT:
			handler = cmd_handlers[13];
			break;
		case SE3_CMD_BOOT_MODE_RESET:
			handler = cmd_handlers[12];
			break;
		default:
			handler = invalid_cmd_handler;
		}
	}

    resp_blocks = se3_exec(handler);

    // set cmdtok
	cmdtok0 = req_hdr.cmdtok[0];
    for (i = 0; i < resp_blocks; i++) {
        resp_hdr.cmdtok[i] = cmdtok0;
		cmdtok0++;
    }
}

uint16_t se3_exec(se3_cmd_func handler)
{
    uint16_t resp_size = 0, tmp;
    uint16_t status = SE3_OK;
    uint16_t nblocks = 0;
    uint16_t data_len;
#if SE3_CONF_CRC
	uint16_t crc;
	uint16_t u16tmp;
#endif

    data_len = se3_req_len_data(req_hdr.len);

#if SE3_CONF_CRC
	// compute CRC
	crc = se3_crc16_update(SE3_REQ_OFFSET_CRC, se3c0.comm.req_hdr, 0);
	if (data_len > 0) {
		crc = se3_crc16_update(data_len, se3c0.comm.req_data, crc);
	}
	if (se3c0.req_hdr.crc != crc) {
		status = SE3_ERR_COMM;
		resp_size = 0;
	}
#endif

	if(status == SE3_OK) {
		status = handler(data_len, comm.req_data, &resp_size, comm.resp_data);
	}

    if (status == SE3_ERR_HW) {
        resp_size = 0;
    }
    else if (resp_size > SE3_RESP_MAX_DATA) {
        status = SE3_ERR_HW;
        resp_size = 0;
    }

    resp_hdr.status = status;

    if (resp_size <= SE3_COMM_BLOCK - SE3_RESP_SIZE_HEADER) {
        nblocks = 1;
        // zero unused memory
        memset(
            comm.resp_data + resp_size, 0,
            SE3_COMM_BLOCK - SE3_RESP_SIZE_HEADER - resp_size);
    }
    else {
        tmp = resp_size - (SE3_COMM_BLOCK - SE3_RESP_SIZE_HEADER);
        nblocks = 1 + tmp / (SE3_COMM_BLOCK - SE3_RESPDATA_SIZE_HEADER);
        if (tmp % (SE3_COMM_BLOCK - SE3_RESPDATA_SIZE_HEADER) != 0) {
            nblocks++;
            // zero unused memory
            memset(
                comm.resp_data + resp_size, 0,
                (SE3_COMM_BLOCK - SE3_RESPDATA_SIZE_HEADER) - (tmp % (SE3_COMM_BLOCK - SE3_RESPDATA_SIZE_HEADER)));
        }
    }

	resp_hdr.len = se3_resp_len_data_and_headers(resp_size);

#if SE3_CONF_CRC
	u16tmp = 1;
	SE3_SET16(se3c0.comm.resp_hdr, SE3_RESP_OFFSET_READY, u16tmp);
	SE3_SET16(se3c0.comm.resp_hdr, SE3_RESP_OFFSET_STATUS, status);
	SE3_SET16(se3c0.comm.resp_hdr, SE3_RESP_OFFSET_LEN, se3c0.resp_hdr.len);
	SE3_SET32(se3c0.comm.resp_hdr, SE3_RESP_OFFSET_CMDTOKEN, se3c0.req_hdr.cmdtok[0]);
	crc = se3_crc16_update(SE3_REQ_OFFSET_CRC, se3c0.comm.resp_hdr, 0);
	if (resp_size > 0) {
		crc = se3_crc16_update(resp_size, se3c0.comm.resp_data, crc);
	}
	se3c0.resp_hdr.crc = crc;
#endif

    return nblocks;
}

uint16_t sec_cmd (uint16_t req_size, const uint8_t* req, uint16_t* resp_size, uint8_t* resp)
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
    if (!login.cryptoctx_initialized) {
        se3_payload_cryptoinit(&(login.cryptoctx), login.key);
        login.cryptoctx_initialized = true;
    }
    if (!se3_payload_decrypt(
        &(login.cryptoctx), req_params.auth, req_params.iv,
        /* !! modifying request */ (uint8_t*)(req  + SE3_L1_AUTH_SIZE + SE3_L1_IV_SIZE),
        (req_size - SE3_L1_AUTH_SIZE - SE3_L1_IV_SIZE) / SE3_L1_CRYPTOBLOCK_SIZE, req_hdr.cmd_flags))
    {
        SE3_TRACE(("[L0d_cmd1] AUTH failed\n"));
        return SE3_ERR_COMM;
    }

    if (login.y) {
        if (memcmp(login.token, req_params.token, SE3_L1_TOKEN_SIZE)) {
            SE3_TRACE(("[L0d_cmd1] login token mismatch\n"));
            return SE3_ERR_ACCESS;
        }
    }

    SE3_GET16(req, SE3_REQ1_OFFSET_LEN, req_params.len);
    SE3_GET16(req, SE3_REQ1_OFFSET_CMD, req_params.cmd);
    if (req_params.cmd < SE3_CMD_MAX) {
        handler = cmd_handlers[req_params.cmd];
    }
    if (handler == NULL) {
        handler = cmd_handlers[15];
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
    if (login.y) {
        memcpy(resp + SE3_RESP1_OFFSET_TOKEN, login.token, SE3_L1_TOKEN_SIZE);
    }
    else {
        memset(resp + SE3_RESP1_OFFSET_TOKEN, 0, SE3_L1_TOKEN_SIZE);
    }
	if (req_hdr.cmd_flags & SE3_CMDFLAG_ENCRYPT) {
		se3_rand(SE3_L1_IV_SIZE, resp_params.iv);
	}
	else {
		memset(resp_params.iv, 0, SE3_L1_IV_SIZE);
	}
    se3_payload_encrypt(
        &(login.cryptoctx), resp_params.auth, resp_params.iv,
        resp + SE3_L1_AUTH_SIZE + SE3_L1_IV_SIZE, (*resp_size - SE3_L1_AUTH_SIZE - SE3_L1_IV_SIZE) / SE3_L1_CRYPTOBLOCK_SIZE, req_hdr.cmd_flags);
    return SE3_OK;
}

uint16_t invalid_cmd_handler (uint16_t req_size, const uint8_t* req, uint16_t* resp_size, uint8_t* resp)
{
    return SE3_ERR_CMD;
}

uint16_t echo (uint16_t req_size, const uint8_t* req, uint16_t* resp_size, uint8_t* resp)
{
    memcpy(resp, req, req_size);
    *resp_size = req_size;
    return SE3_OK;
}

uint16_t factory_init(uint16_t req_size, const uint8_t* req, uint16_t* resp_size, uint8_t* resp)
{
    enum {
        OFF_SERIAL = 0
    };
    const uint8_t* serial_i = req + OFF_SERIAL;
    se3_flash_it it;

	if (serial.written) {
		return SE3_ERR_STATE;
	}

    se3_flash_it_init(&it);
    if (!se3_flash_it_new(&it, SE3_FLASH_TYPE_SERIAL, SE3_SERIAL_SIZE)) {
        return SE3_ERR_HW;
    }
    if (!se3_flash_it_write(&it, 0, serial_i, SE3_SERIAL_SIZE)) {
        return SE3_ERR_HW;
    }

    memcpy(serial.data, serial_i, SE3_SERIAL_SIZE);
    serial.written = true;
    return SE3_OK;
}

uint16_t bootmode_reset(uint16_t req_size, const uint8_t* req, uint16_t* resp_size, uint8_t* resp)
{

	if(!(se3_flash_bootmode_reset(SE3_FLASH_SIGNATURE_ADDR, SE3_FLASH_SIGNATURE_SIZE)))
		return SE3_ERR_HW;

	return SE3_OK;
}

uint16_t cmd_error(uint16_t req_size, const uint8_t* req, uint16_t* resp_size, uint8_t* resp)
{
    return SE3_ERR_CMD;
}

uint16_t challenge(uint16_t req_size, const uint8_t* req, uint16_t* resp_size, uint8_t* resp)
{
   // static B5_tSha256Ctx sha;
    uint8_t pin[SE3_L1_PIN_SIZE];
    struct {
        const uint8_t* cc1;
        const uint16_t access;
        const uint8_t* cc2;
    } req_params;
    struct {
        uint8_t* sc;
        uint8_t* sresp;
    } resp_params;

    if (req_size != SE3_CMD1_CHALLENGE_REQ_SIZE) {
        SE3_TRACE(("[L1d_challenge] req size mismatch\n"));
        return SE3_ERR_PARAMS;
    }

    req_params.cc1 = req + SE3_CMD1_CHALLENGE_REQ_OFF_CC1;
    req_params.cc2 = req + SE3_CMD1_CHALLENGE_REQ_OFF_CC2;
    SE3_GET16(req, SE3_CMD1_CHALLENGE_REQ_OFF_ACCESS, req_params.access);
    resp_params.sc = resp + SE3_CMD1_CHALLENGE_RESP_OFF_SC;
    resp_params.sresp = resp + SE3_CMD1_CHALLENGE_RESP_OFF_SRESP;

	if (login.y) {
		SE3_TRACE(("[L1d_challenge] already logged in"));
		return SE3_ERR_STATE;
	}

    // default pin is zero, if no record is found
    memset(pin, 0, SE3_L1_PIN_SIZE);
    switch (req_params.access) {
    case SE3_ACCESS_USER:
        record_get(SE3_RECORD_TYPE_USERPIN, pin);
        break;
    case SE3_ACCESS_ADMIN:
        record_get(SE3_RECORD_TYPE_ADMINPIN, pin);
        break;
    default:
        return SE3_ERR_PARAMS;
	}

	if (SE3_L1_CHALLENGE_SIZE != se3_rand(SE3_L1_CHALLENGE_SIZE, resp_params.sc)) {
		SE3_TRACE(("[L1d_challenge] se3_rand failed"));
		return SE3_ERR_HW;
	}

	// cresp = PBKDF2(HMACSHA256, pin, sc, SE3_L1_CHALLENGE_ITERATIONS, SE3_CHALLENGE_SIZE)
//	dispatcher_handler(PBKDF2HmacSha256, pin, SE3_L1_PIN_SIZE, resp_params.sc,
//		SE3_L1_CHALLENGE_SIZE, SE3_L1_CHALLENGE_ITERATIONS, login.challenge, SE3_L1_CHALLENGE_SIZE);

	// sresp = PBKDF2(HMACSHA256, pin, cc1, SE3_L1_CHALLENGE_ITERATIONS, SE3_CHALLENGE_SIZE)//
//	dispatcher_handler(PBKDF2HmacSha256,pin, SE3_L1_PIN_SIZE, req_params.cc1,
//		SE3_L1_CHALLENGE_SIZE, SE3_L1_CHALLENGE_ITERATIONS, resp_params.sresp, SE3_L1_CHALLENGE_SIZE);

	// key = PBKDF2(HMACSHA256, pin, cc2, 1, SE3_L1_PIN_SIZE)
//	dispatcher_handler(PBKDF2HmacSha256, pin, SE3_L1_PIN_SIZE, req_params.cc2,
//		SE3_L1_CHALLENGE_SIZE, 1, login.key, SE3_L1_PIN_SIZE);

	login.challenge_access = req_params.access;

    *resp_size = SE3_CMD1_CHALLENGE_RESP_SIZE;
	return SE3_OK;
}

uint16_t cmd_login(uint16_t req_size, const uint8_t* req, uint16_t* resp_size, uint8_t* resp)
{
    struct {
        const uint8_t* cresp;
    } req_params;
    struct {
        uint8_t* token;
    } resp_params;
    uint16_t access;

    if (req_size != SE3_CMD1_LOGIN_REQ_SIZE) {
        SE3_TRACE(("[L1d_login] req size mismatch\n"));
        return SE3_ERR_PARAMS;
    }

	if (login.y) {
		SE3_TRACE(("[L1d_login] already logged in"));
		return SE3_ERR_STATE;
	}
	if (SE3_ACCESS_MAX == login.challenge_access) {
		SE3_TRACE(("[L1d_login] not waiting for challenge response"));
		return SE3_ERR_STATE;
	}

    req_params.cresp = req + SE3_CMD1_LOGIN_REQ_OFF_CRESP;
    resp_params.token = resp + SE3_CMD1_LOGIN_RESP_OFF_TOKEN;

	access = login.challenge_access;
	login.challenge_access = SE3_ACCESS_MAX;
	if (memcmp(req_params.cresp, (uint8_t*)login.challenge, 32)) {
		SE3_TRACE(("[L1d_login] challenge response mismatch"));
		return SE3_ERR_PIN;
	}

	if (SE3_L1_TOKEN_SIZE != se3_rand(SE3_L1_TOKEN_SIZE, (uint8_t*)login.token)) {
		SE3_TRACE(("[L1d_login] random failed"));
		return SE3_ERR_HW;
	}
	memcpy(resp_params.token, (uint8_t*)login.token, 16);
	login.y = 1;
	login.access = access;

    *resp_size = SE3_CMD1_LOGIN_RESP_SIZE;
	return SE3_OK;
}

uint16_t logout(uint16_t req_size, const uint8_t* req, uint16_t* resp_size, uint8_t* resp)
{
    if (req_size != 0) {
        SE3_TRACE(("[L1d_logout] req size mismatch\n"));
        return SE3_ERR_PARAMS;
    }
	if (!login.y) {
		SE3_TRACE(("[L1d_logout] not logged in\n"));
		return SE3_ERR_ACCESS;
	}
	login_cleanup();
	return SE3_OK;
}

uint16_t key_edit(uint16_t req_size, const uint8_t* req, uint16_t* resp_size, uint8_t* resp)
{
    struct {
        uint16_t op;
        uint32_t id;
        uint32_t validity;
        uint16_t data_len;
        uint16_t name_len;
        const uint8_t* data;
        const uint8_t* name;
    } req_params;

    se3_flash_key key;
	bool equal;
    se3_flash_it it = { .addr = NULL };

    if (req_size < SE3_CMD1_KEY_EDIT_REQ_OFF_DATA_AND_NAME) {
        SE3_TRACE(("[L1d_key_edit] req size mismatch\n"));
        return SE3_ERR_PARAMS;
    }

    if (!login.y) {
        SE3_TRACE(("[L1d_key_edit] not logged in\n"));
        return SE3_ERR_ACCESS;
    }

    SE3_GET16(req, SE3_CMD1_KEY_EDIT_REQ_OFF_OP, req_params.op);
    SE3_GET32(req, SE3_CMD1_KEY_EDIT_REQ_OFF_ID, req_params.id);
    SE3_GET32(req, SE3_CMD1_KEY_EDIT_REQ_OFF_VALIDITY, req_params.validity);
    SE3_GET16(req, SE3_CMD1_KEY_EDIT_REQ_OFF_DATA_LEN, req_params.data_len);
    SE3_GET16(req, SE3_CMD1_KEY_EDIT_REQ_OFF_NAME_LEN, req_params.name_len);
    req_params.data = req + SE3_CMD1_KEY_EDIT_REQ_OFF_DATA_AND_NAME;
    req_params.name = req + SE3_CMD1_KEY_EDIT_REQ_OFF_DATA_AND_NAME + req_params.data_len;

    // check params
    if ((req_params.data_len > SE3_KEY_DATA_MAX) || (req_params.name_len > SE3_KEY_NAME_MAX)) {
        return SE3_ERR_PARAMS;
    }

    key.id = req_params.id;
    key.data_size = req_params.data_len;
    key.name_size = req_params.name_len;
    key.validity = req_params.validity;
    key.data = (uint8_t*)req_params.data;
    key.name = (uint8_t*)req_params.name;

    se3_flash_it_init(&it);
    if (!se3_key_find(key.id, &it)) {
        it.addr = NULL;
    }

    switch (req_params.op) {
    case SE3_KEY_OP_INSERT:
        if (NULL != it.addr) {
            return SE3_ERR_RESOURCE;
        }
        if (!se3_key_new(&it, &key)) {
            SE3_TRACE(("[L1d_key_edit] se3_key_new failed\n"));
            return SE3_ERR_MEMORY;
        }
        break;
    case SE3_KEY_OP_DELETE:
        if (NULL == it.addr) {
            return SE3_ERR_RESOURCE;
        }
        if (!se3_flash_it_delete(&it)) {
            return SE3_ERR_HW;
        }
        break;
    case SE3_KEY_OP_UPSERT:
		equal = false;
        if (NULL != it.addr) {
            // do not replace if equal
			equal = se3_key_equal(&it, &key);
			if (!equal) {
				if (!se3_flash_it_delete(&it)) {
					return SE3_ERR_HW;
				}
			}
        }
        it.addr = NULL;
		if (!equal) {
			if (!se3_key_new(&it, &key)) {
				SE3_TRACE(("[L1d_key_edit] se3_key_new failed\n"));
				return SE3_ERR_MEMORY;
			}
		}
        break;
    default:
        SE3_TRACE(("[L1d_key_edit] invalid op\n"));
        return SE3_ERR_PARAMS;
    }

	return SE3_OK;
}

uint16_t key_list(uint16_t req_size, const uint8_t* req, uint16_t* resp_size, uint8_t* resp)
{
    struct {
        uint16_t skip;
        uint16_t nmax;
		uint8_t* salt;
    } req_params;
    struct {
        uint16_t count;
    } resp_params;

    se3_flash_key key;
    se3_flash_it it = { .addr = NULL };
    size_t size = 0;
    size_t key_info_size = 0;
    uint8_t* p;
    uint16_t skip;
    uint8_t tmp[SE3_KEY_NAME_MAX];
	uint8_t fingerprint[SE3_KEY_FINGERPRINT_SIZE];

    if (req_size != SE3_CMD1_KEY_LIST_REQ_SIZE) {
        SE3_TRACE(("[L1d_key_list] req size mismatch\n"));
        return SE3_ERR_PARAMS;
    }

    if (!login.y) {
        SE3_TRACE(("[L1d_key_list] not logged in\n"));
        return SE3_ERR_ACCESS;
    }

    SE3_GET16(req, SE3_CMD1_KEY_LIST_REQ_OFF_SKIP, req_params.skip);
    SE3_GET16(req, SE3_CMD1_KEY_LIST_REQ_OFF_NMAX, req_params.nmax);
	req_params.salt = (uint8_t*) (req + SE3_CMD1_KEY_LIST_REQ_OFF_SALT);

	/* ! will write key data to request buffer */
	key.data = (uint8_t*)req + ((SE3_CMD1_KEY_LIST_REQ_SIZE / 16) + 1) * 16;
    key.name = tmp;
    resp_params.count = 0;
    skip = req_params.skip;
    size = SE3_CMD1_KEY_LIST_RESP_OFF_KEYINFO;
    p = resp + SE3_CMD1_KEY_LIST_RESP_OFF_KEYINFO;
    while (se3_flash_it_next(&it)) {
        if (it.type == SE3_TYPE_KEY) {
            if (skip) {
                skip--;
                continue;
            }
            se3_key_read(&it, &key);
            key_info_size = SE3_CMD1_KEY_LIST_KEYINFO_OFF_NAME + key.name_size;
            if (size + key_info_size > SE3_RESP1_MAX_DATA) {
                break;
            }
			se3_key_fingerprint(&key, req_params.salt, fingerprint);
            SE3_SET32(p, SE3_CMD1_KEY_LIST_KEYINFO_OFF_ID, key.id);
            SE3_SET32(p, SE3_CMD1_KEY_LIST_KEYINFO_OFF_VALIDITY, key.validity);
            SE3_SET16(p, SE3_CMD1_KEY_LIST_KEYINFO_OFF_DATA_LEN, key.data_size);
            SE3_SET16(p, SE3_CMD1_KEY_LIST_KEYINFO_OFF_NAME_LEN, key.name_size);
			memcpy(p + SE3_CMD1_KEY_LIST_KEYINFO_OFF_FINGERPRINT, fingerprint, SE3_KEY_FINGERPRINT_SIZE);
            memcpy(p + SE3_CMD1_KEY_LIST_KEYINFO_OFF_NAME, key.name, key.name_size);
            p += key_info_size;
            size += key_info_size;
            (resp_params.count)++;
            if (resp_params.count >= req_params.nmax) {
                break;
            }
        }
    }
	memset(key.data, 0, SE3_KEY_DATA_MAX);

    SE3_SET16(resp, SE3_CMD1_KEY_LIST_RESP_OFF_COUNT, resp_params.count);
    *resp_size = (uint16_t)size;

    return SE3_OK;
}

uint16_t config(uint16_t req_size, const uint8_t* req, uint16_t* resp_size, uint8_t* resp)
{
    struct {
        uint16_t type;
        uint16_t op;
        const uint8_t* value;
    } req_params;
    struct {
        uint8_t* value;
    } resp_params;

    if (!login.y) {
        SE3_TRACE(("[L1d_config] not logged in\n"));
        return SE3_ERR_ACCESS;
    }

    SE3_GET16(req, SE3_CMD1_CONFIG_REQ_OFF_ID, req_params.type);
    SE3_GET16(req, SE3_CMD1_CONFIG_REQ_OFF_OP, req_params.op);
    req_params.value = req + SE3_CMD1_CONFIG_REQ_OFF_VALUE;
    resp_params.value = resp + SE3_CMD1_CONFIG_RESP_OFF_VALUE;

    // check params
    if (req_params.type >= SE3_RECORD_MAX) {
        SE3_TRACE(("[L1d_config] type out of range\n"));
        return SE3_ERR_PARAMS;
    }
    switch (req_params.op) {
    case SE3_CONFIG_OP_GET:
    case SE3_CONFIG_OP_SET:
        if (req_size != SE3_CMD1_CONFIG_REQ_OFF_VALUE + SE3_RECORD_SIZE) {
            SE3_TRACE(("[L1d_config] req size mismatch\n"));
            return SE3_ERR_PARAMS;
        }
        break;
    default:
        SE3_TRACE(("[L1d_config] op invalid\n"));
        return SE3_ERR_PARAMS;
    }

    if (req_params.op == SE3_CONFIG_OP_GET) {
        // check access
        if (login.access < records[req_params.type].read_access) {
            SE3_TRACE(("[L1d_config] insufficient access\n"));
            return SE3_ERR_ACCESS;
        }
        if (!record_get(req_params.type, resp_params.value)) {
            return SE3_ERR_RESOURCE;
        }
        *resp_size = SE3_RECORD_SIZE;
    }
    else if (req_params.op == SE3_CONFIG_OP_SET) {
        // check access
        if (login.access < records[req_params.type].write_access) {
            SE3_TRACE(("[L1d_config] insufficient access\n"));
            return SE3_ERR_ACCESS;
        }
        if (!record_set(req_params.type, req_params.value)) {
            return SE3_ERR_MEMORY;
        }
    }
    else {
        SE3_TRACE(("[L1d_config] invalid op\n"));
        return SE3_ERR_PARAMS;
    }

	return SE3_OK;
}

/*
uint16_t crypto_init(uint16_t req_size, const uint8_t* req, uint16_t* resp_size, uint8_t* resp)
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

    if (!login.y) {
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

		if (key.validity < time_get() || !now_initialized_get()) {
			SE3_TRACE(("[L1d_crypto_init] key expired\n"));
			return SE3_ERR_EXPIRED;
		}
    }

    resp_params.sid = SE3_SESSION_INVALID;
    sid = se3_mem_alloc(&(sessions), L1d_algo_table[req_params.algo].size);
    if (sid >= 0) {
        resp_params.sid = (uint32_t)sid;
    }

    if (resp_params.sid == SE3_SESSION_INVALID) {
        SE3_TRACE(("[L1d_crypto_init] cannot allocate session\n"));
        return SE3_ERR_MEMORY;
    }

    ctx = se3_mem_ptr(&(sessions), sid);
    if (ctx == NULL) {
        // this should not happen
        SE3_TRACE(("[L1d_crypto_init] NULL session pointer\n"));
        return SE3_ERR_HW;
    }

    status = handler(&key, req_params.mode, ctx);

    if (SE3_OK != status) {
        // free the allocated session
        se3_mem_free(&(sessions), (int32_t)resp_params.sid);

        SE3_TRACE(("[L1d_crypto_init] crypto handler failed\n"));
        return status;
    }

    // link session to algo
    sessions_algo[resp_params.sid] = req_params.algo;

    SE3_SET32(resp, SE3_CMD1_CRYPTO_INIT_RESP_OFF_SID, resp_params.sid);

    *resp_size = SE3_CMD1_CRYPTO_INIT_RESP_SIZE;

	return SE3_OK;
}
*/

uint16_t crypto_update(uint16_t req_size, const uint8_t* req, uint16_t* resp_size, uint8_t* resp)
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

    if (!login.y) {
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

    algo = sessions_algo[req_params.sid];
    if (algo >= SE3_ALGO_MAX) {
        SE3_TRACE(("[L1d_crypto_update] invalid algo for this sid (wrong sid?)\n"));
        return SE3_ERR_RESOURCE;
    }

    handler = L1d_algo_table[algo].update;
    if (handler == NULL) {
        SE3_TRACE(("[L1d_crypto_update] invalid crypto handler for this algo (wrong sid?)\n"));
        return SE3_ERR_RESOURCE;
    }

    ctx = se3_mem_ptr(&(sessions), (int32_t)req_params.sid);
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
        se3_mem_free(&(sessions), (int32_t)req_params.sid);
    }

    SE3_SET16(resp, SE3_CMD1_CRYPTO_UPDATE_RESP_OFF_DATAOUT_LEN, resp_params.dataout_len);
    *resp_size = SE3_CMD1_CRYPTO_UPDATE_RESP_OFF_DATA + resp_params.dataout_len;

    return SE3_OK;
}

uint16_t crypto_set_time(uint16_t req_size, const uint8_t* req, uint16_t* resp_size, uint8_t* resp)
{
    struct {
        uint32_t devtime;
    } req_params;

    if (req_size != SE3_CMD1_CRYPTO_SET_TIME_REQ_SIZE) {
        SE3_TRACE(("[L1d_crypto_set_time] req size mismatch\n"));
        return SE3_ERR_PARAMS;
    }
    if (!login.y) {
        SE3_TRACE(("[L1d_crypto_set_time] not logged in\n"));
        return SE3_ERR_ACCESS;
    }

    SE3_GET32(req, SE3_CMD1_CRYPTO_SET_TIME_REQ_OFF_DEVTIME, req_params.devtime);

    time_set((uint64_t)req_params.devtime);

    return SE3_OK;
}

uint16_t crypto_list(uint16_t req_size, const uint8_t* req, uint16_t* resp_size, uint8_t* resp)
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
    if (!login.y) {
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

