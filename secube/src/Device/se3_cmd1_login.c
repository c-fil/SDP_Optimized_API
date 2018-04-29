


/** \brief Get a login challenge from the server
 *  
 *  challenge : (cc1[32], cc2[32], access:ui16) => (sc[32], sresp[32])
 */


/** \brief respond to challenge, completing login
 *  
 *  login : (cresp[32]) => (tok[16])
 */
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
uint16_t logout(uint16_t req_size, const uint8_t* req, uint16_t* resp_size, uint8_t* resp)
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

