/**
 *  \file se3_cmd1_config.c
 *  \author Nicola Ferri
 *  \brief L1 handlers for configuration record operations
 */

#include "se3_cmd1_config.h"

/** \brief set or get configuration record
 *  
 *  config : (type:ui16, op:ui16, value[32]) => (value[32])
 */
uint16_t L1d_config(uint16_t req_size, const uint8_t* req, uint16_t* resp_size, uint8_t* resp)
{
    struct {
        uint16_t type;
        uint16_t op;
        const uint8_t* value;
    } req_params;
    struct {
        uint8_t* value;
    } resp_params;
    
    if (!se3c1.login.y) {
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
        if (se3c1.login.access < se3c1.records[req_params.type].read_access) {
            SE3_TRACE(("[L1d_config] insufficient access\n"));
            return SE3_ERR_ACCESS;
        }
        if (!se3c1_record_get(req_params.type, resp_params.value)) {
            return SE3_ERR_RESOURCE;
        }
        *resp_size = SE3_RECORD_SIZE;
    }
    else if (req_params.op == SE3_CONFIG_OP_SET) {
        // check access
        if (se3c1.login.access < se3c1.records[req_params.type].write_access) {
            SE3_TRACE(("[L1d_config] insufficient access\n"));
            return SE3_ERR_ACCESS;
        }
        if (!se3c1_record_set(req_params.type, req_params.value)) {
            return SE3_ERR_MEMORY;
        }
    }
    else {
        SE3_TRACE(("[L1d_config] invalid op\n"));
        return SE3_ERR_PARAMS;
    }

	return SE3_OK;
}


