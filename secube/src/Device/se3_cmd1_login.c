/**
 *  \file se3_cmd1_login.c
 *  \author Nicola Ferri
 *  \brief L1 handlers for login operations
 */

#include "se3_cmd1_login.h"
#ifndef CUBESIM
#include "se3_rand.h"
#endif

/*
    Challenge-based authentication
    
	Password-Based Key Derivation Function 2
			PBKDF2(PRF, Password, Salt, c, dkLen)

	cc1     client(=host) challenge 1
			random(32)
	cc2     client(=host) challenge 2
			random(32)
	sc      server(=device) challenge
			random(32)
	cresp   client(=host) response
			PBKDF2(HMAC-SHA256, pin, sc, SE3_L1_CHALLENGE_ITERATIONS, SE3_CHALLENGE_SIZE)
	sresp   server(=device) response
			PBKDF2(HMAC-SHA256, pin, cc1, SE3_L1_CHALLENGE_ITERATIONS, SE3_CHALLENGE_SIZE)
	key     session key for enc/auth of L1 protocol
			PBKDF2(HMAC-SHA256, pin, cc2, 1, SE3_L1_PIN_SIZE)

	L1_challenge (not encrypted)
		host
			generate cc1,cc2
			send cc1,cc2
		device
			generate sc
			compute sresp, cresp, key
			send sresp
	L1_login (encrypted with key)
		host
			compute sresp, cresp, key
			check sresp
			send cresp
		device
			check cresp
			send token  <- the token is transmitted encrypted
*/

/** \brief Get a login challenge from the server
 *  
 *  challenge : (cc1[32], cc2[32], access:ui16) => (sc[32], sresp[32])
 */
uint16_t L1d_challenge(uint16_t req_size, const uint8_t* req, uint16_t* resp_size, uint8_t* resp)
{
    static B5_tSha256Ctx sha;
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

	if (se3c1.login.y) {
		SE3_TRACE(("[L1d_challenge] already logged in"));
		return SE3_ERR_STATE;
	}

    // default pin is zero, if no record is found
    memset(pin, 0, SE3_L1_PIN_SIZE);
    switch (req_params.access) {
    case SE3_ACCESS_USER:
        se3c1_record_get(SE3_RECORD_TYPE_USERPIN, pin);
        break;
    case SE3_ACCESS_ADMIN:
        se3c1_record_get(SE3_RECORD_TYPE_ADMINPIN, pin);
        break;
    default:
        return SE3_ERR_PARAMS;
	}

	if (SE3_L1_CHALLENGE_SIZE != se3_rand(SE3_L1_CHALLENGE_SIZE, resp_params.sc)) {
		SE3_TRACE(("[L1d_challenge] se3_rand failed"));
		return SE3_ERR_HW;
	}

	// cresp = PBKDF2(HMACSHA256, pin, sc, SE3_L1_CHALLENGE_ITERATIONS, SE3_CHALLENGE_SIZE)
	PBKDF2HmacSha256(pin, SE3_L1_PIN_SIZE, resp_params.sc, 
		SE3_L1_CHALLENGE_SIZE, SE3_L1_CHALLENGE_ITERATIONS, se3c1.login.challenge, SE3_L1_CHALLENGE_SIZE);

	// sresp = PBKDF2(HMACSHA256, pin, cc1, SE3_L1_CHALLENGE_ITERATIONS, SE3_CHALLENGE_SIZE)
	PBKDF2HmacSha256(pin, SE3_L1_PIN_SIZE, req_params.cc1,
		SE3_L1_CHALLENGE_SIZE, SE3_L1_CHALLENGE_ITERATIONS, resp_params.sresp, SE3_L1_CHALLENGE_SIZE);

	// key = PBKDF2(HMACSHA256, pin, cc2, 1, SE3_L1_PIN_SIZE)
	PBKDF2HmacSha256(pin, SE3_L1_PIN_SIZE, req_params.cc2,
		SE3_L1_CHALLENGE_SIZE, 1, se3c1.login.key, SE3_L1_PIN_SIZE);

	se3c1.login.challenge_access = req_params.access;

    *resp_size = SE3_CMD1_CHALLENGE_RESP_SIZE;
	return SE3_OK;
}

/** \brief respond to challenge, completing login
 *  
 *  login : (cresp[32]) => (tok[16])
 */
uint16_t L1d_login(uint16_t req_size, const uint8_t* req, uint16_t* resp_size, uint8_t* resp)
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

	if (se3c1.login.y) {
		SE3_TRACE(("[L1d_login] already logged in"));
		return SE3_ERR_STATE;
	}
	if (SE3_ACCESS_MAX == se3c1.login.challenge_access) {
		SE3_TRACE(("[L1d_login] not waiting for challenge response"));
		return SE3_ERR_STATE;
	}

    req_params.cresp = req + SE3_CMD1_LOGIN_REQ_OFF_CRESP;
    resp_params.token = resp + SE3_CMD1_LOGIN_RESP_OFF_TOKEN;

	access = se3c1.login.challenge_access;
	se3c1.login.challenge_access = SE3_ACCESS_MAX;
	if (memcmp(req_params.cresp, (uint8_t*)se3c1.login.challenge, 32)) {
		SE3_TRACE(("[L1d_login] challenge response mismatch"));
		return SE3_ERR_PIN;
	}

	if (SE3_L1_TOKEN_SIZE != se3_rand(SE3_L1_TOKEN_SIZE, (uint8_t*)se3c1.login.token)) {
		SE3_TRACE(("[L1d_login] random failed"));
		return SE3_ERR_HW;
	}
	memcpy(resp_params.token, (uint8_t*)se3c1.login.token, 16);
	se3c1.login.y = 1;
	se3c1.login.access = access;

    *resp_size = SE3_CMD1_LOGIN_RESP_SIZE;
	return SE3_OK;
}


/** \brief Log out and release resources
 *  
 *  logout : () => ()
 */
uint16_t L1d_logout(uint16_t req_size, const uint8_t* req, uint16_t* resp_size, uint8_t* resp)
{
    if (req_size != 0) {
        SE3_TRACE(("[L1d_logout] req size mismatch\n"));
        return SE3_ERR_PARAMS;
    }
	if (!se3c1.login.y) {
		SE3_TRACE(("[L1d_logout] not logged in\n"));
		return SE3_ERR_ACCESS;
	}
	se3c1_login_cleanup();
	return SE3_OK;
}

