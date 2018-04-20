/**
 *  \file se3_cmd.c
 *  \author Nicola Ferri
 *  \brief L0 command dispatch and execute
 */

#include "se3_cmd.h"
#include "se3_cmd0.h"
#include "se3_cmd1.h"
#include "se3c1.h"
#include "crc16.h"

static uint16_t invalid_cmd_handler(uint16_t req_size, const uint8_t* req, uint16_t* resp_size, uint8_t* resp)
{
    return SE3_ERR_CMD;
}

static uint16_t se3_exec(se3_cmd_func handler)
{
    uint16_t resp_size = 0, tmp;
    uint16_t status = SE3_OK;
    uint16_t nblocks = 0;
    uint16_t data_len;
#if SE3_CONF_CRC
	uint16_t crc;
	uint16_t u16tmp;
#endif

    data_len = se3_req_len_data(se3c0.req_hdr.len);

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
		status = handler(data_len, se3c0.comm.req_data, &resp_size, se3c0.comm.resp_data);
	}

    if (se3c0.hwerror) {
        status = SE3_ERR_HW;
        resp_size = 0;
        se3c0.hwerror = false;
    }
    else if (resp_size > SE3_RESP_MAX_DATA) {
        status = SE3_ERR_HW;
        resp_size = 0;
    }

    se3c0.resp_hdr.status = status;

    if (resp_size <= SE3_COMM_BLOCK - SE3_RESP_SIZE_HEADER) {
        nblocks = 1;
        // zero unused memory
        memset(
            se3c0.comm.resp_data + resp_size, 0,
            SE3_COMM_BLOCK - SE3_RESP_SIZE_HEADER - resp_size);
    }
    else {
        tmp = resp_size - (SE3_COMM_BLOCK - SE3_RESP_SIZE_HEADER);
        nblocks = 1 + tmp / (SE3_COMM_BLOCK - SE3_RESPDATA_SIZE_HEADER);
        if (tmp % (SE3_COMM_BLOCK - SE3_RESPDATA_SIZE_HEADER) != 0) {
            nblocks++;
            // zero unused memory
            memset(
                se3c0.comm.resp_data + resp_size, 0,
                (SE3_COMM_BLOCK - SE3_RESPDATA_SIZE_HEADER) - (tmp % (SE3_COMM_BLOCK - SE3_RESPDATA_SIZE_HEADER)));
        }
    }

	se3c0.resp_hdr.len = se3_resp_len_data_and_headers(resp_size);

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

void se3_cmd_execute()
{
    uint16_t req_blocks = 1, resp_blocks = 1;
    size_t i;
    se3_cmd_func handler = NULL;
	uint32_t cmdtok0;

    req_blocks = se3c0.req_hdr.len / SE3_COMM_BLOCK;
    if (se3c0.req_hdr.len % SE3_COMM_BLOCK != 0) {
        req_blocks++;
    }
    if (req_blocks > SE3_COMM_N - 1) {
        // should not happen anyway
        resp_blocks = 0;
        goto update_comm;
    }
    for (i = 1; i < req_blocks; i++) {
        if (se3c0.req_hdr.cmdtok[i] != se3c0.req_hdr.cmdtok[i - 1] + 1) {
            resp_blocks = 0;
            goto update_comm;
        }
    }

	if (handler == NULL) {
		switch (se3c0.req_hdr.cmd) {
		case SE3_CMD0_L1:
			handler = L0d_cmd1;
			break;
		case SE3_CMD0_ECHO:
			handler = L0d_echo;
			break;
		case SE3_CMD0_FACTORY_INIT:
			handler = L0d_factory_init;
			break;
		case SE3_CMD0_BOOT_MODE_RESET:
			handler = L0d_bootmode_reset;
			break;
		default:
			handler = invalid_cmd_handler;
		}
	}

    resp_blocks = se3_exec(handler);

    // set cmdtok
	cmdtok0 = se3c0.req_hdr.cmdtok[0];
    for (i = 0; i < resp_blocks; i++) {
        se3c0.resp_hdr.cmdtok[i] = cmdtok0;
		cmdtok0++;
    }
    

update_comm:
    // update comm response bit map
    se3c0.comm.resp_bmap = SE3_BMAP_MAKE(resp_blocks);
}

