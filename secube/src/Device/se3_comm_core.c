#include "se3_comm_core.h"

const uint8_t se3_hello[SE3_HELLO_SIZE] = {
	'H', 'e', 'l', 'l', 'o', ' ', 'S', 'E',
    'c', 'u', 'b', 'e', 0, 0, 0, 0,
    0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0
};

uint8_t se3_comm_request_buffer[SE3_COMM_N*SE3_COMM_BLOCK];
uint8_t se3_comm_response_buffer[SE3_COMM_N*SE3_COMM_BLOCK];


void se3_communication_init(){
    memset(&comm, 0, sizeof(SE3_COMM_STATUS));
//TODO: MEMSET DI QUALSIASI COSA
    comm.req_hdr = se3_comm_request_buffer;
    //comm.req_hdr = malloc(SE3_COMM_N*SE3_COMM_BLOCK * sizeof (uint8_t));
   // memset(comm.req_hdr, 0, SE3_COMM_N*SE3_COMM_BLOCK * sizeof (uint8_t));
    comm.req_data = se3_comm_request_buffer + SE3_REQ_SIZE_HEADER;
    //comm.req_data =  comm.req_hdr + SE3_REQ_SIZE_HEADER;
    comm.resp_hdr = se3_comm_response_buffer;
    //comm.resp_hdr = malloc(SE3_COMM_N*SE3_COMM_BLOCK * sizeof (uint8_t));
   // memset(comm.resp_hdr, 0, SE3_COMM_N*SE3_COMM_BLOCK * sizeof (uint8_t));
    comm.resp_data = se3_comm_response_buffer + SE3_RESP_SIZE_HEADER;
  //  comm.resp_data =  comm.resp_hdr + SE3_RESP_SIZE_HEADER;

    comm.magic_bmap = SE3_BMAP_MAKE(16); //set 16 LSB bit to 1
    comm.magic_ready = false;
    comm.req_bmap = SE3_BMAP_MAKE(1); //LSB set to 1
    comm.locked = false;
    comm.req_ready = false;
    comm.req_bmap = SE3_BMAP_MAKE(32);
    comm.resp_ready = true;
    comm.resp_bmap = 0;

}

//TODO:fa schifo perche' comm e' gigante e lui non pulisce niente
void se3_proto_request_reset()
{
    comm.req_ready = false;
    comm.req_bmap = SE3_BMAP_MAKE(32);
}

int32_t se3_proto_recv(uint8_t lun, const uint8_t* buf, uint32_t blk_addr, uint16_t blk_len)
{int32_t r = SE3_PROTO_OK;
uint32_t block;
int index;
const uint8_t* data = buf;

s3_storage_range range = {
	.first = 0,
	.count = 0
};
block = blk_addr;
for (block = blk_addr; block < blk_addr + blk_len; block++) {
	if (block == 0) {
		#ifdef SE3_DEBUG_SD
		uint8_t debug_buffer1[512] = "[proto_recv] block = 0\n\0";
		MYPRINTF(debug_buffer1,(uint32_t)(BASE_DEBUG_ADDRESS + debug_count++));
		#endif
		r = se3_storage_range_add(&range, lun, (uint8_t*)data, block, range_write);
		if (SE3_PROTO_OK != r){
			#ifdef SE3_DEBUG_SD
			uint8_t debug_buffer2[512] = "[proto_recv] SE3_PROTO_OK != r\n\0";
			MYPRINTF(debug_buffer2,(uint32_t)(BASE_DEBUG_ADDRESS + debug_count++));
	#endif
			return r;
		}
	}
	else {
        if (block_is_magic(data)) {
#ifdef SE3_DEBUG_SD
        	uint8_t debug_buffer3[512] = "[proto_recv] Block is magic\n\0";
        	MYPRINTF(debug_buffer3,(uint32_t)(BASE_DEBUG_ADDRESS + debug_count++));
#endif
            // magic block
            if (comm.locked) {
                // if locked, prevent initialization
#ifdef SE3_DEBUG_SD
            	uint8_t debug_buffer4[512] = "[proto_recv] comm.locked = true\n\0";
            	MYPRINTF(debug_buffer4,(uint32_t)(BASE_DEBUG_ADDRESS + debug_count++));
#endif
                continue;
            }
            if (comm.magic_ready) {
#ifdef SE3_DEBUG_SD
            	uint8_t debug_buffer5[512] = "[proto_recv] comm.magic_ready = true\n\0";
            	MYPRINTF(debug_buffer5,(uint32_t)(BASE_DEBUG_ADDRESS + debug_count++));
#endif
                // if magic already initialized, reset
                comm.magic_ready = false;
                comm.magic_bmap = SE3_BMAP_MAKE(16);
                for (index = 0; index < 16; index++)
                    comm.blocks[index] = 0;
            }
            // store block in blocks map
            index = data[SE3_COMM_BLOCK - 1];
            comm.blocks[index] = block;
            SE3_BIT_CLEAR(comm.magic_bmap, index);
            if (comm.magic_bmap == 0) {
#ifdef SE3_DEBUG_SD
            	uint8_t debug_buffer8[512] = "[proto_recv] comm.magic bmap = 0\n\0";
            	MYPRINTF(debug_buffer8,(uint32_t)(BASE_DEBUG_ADDRESS + debug_count++));
#endif
                comm.magic_ready = true;
            }
        }
        else{
            // not a magic block
#ifdef SE3_DEBUG_SD
        	uint8_t debug_buffer6[512] = "[proto_recv] Block is not magic\n\0";
        	MYPRINTF(debug_buffer6,(uint32_t)(BASE_DEBUG_ADDRESS + debug_count++));
#endif



            if (!comm.magic_ready) {
#ifdef SE3_DEBUG_SD
            	uint8_t debug_buffer7[512] = "[proto_recv] comm.magic_ready = false\n\0";
            	MYPRINTF(debug_buffer7,(uint32_t)(BASE_DEBUG_ADDRESS + debug_count++));
#endif

                // magic file has not been written yet. forward
                r = se3_storage_range_add(&range, lun, (uint8_t*)data, block, range_write);
                if (SE3_PROTO_OK != r) return r;
            }
            else {
#ifdef SE3_DEBUG_SD
            	uint8_t debug_buffer[512] = "[proto_recv] comm.magic_ready = true, may be a command! Writing magic file\n\0";
            	MYPRINTF(debug_buffer,(uint32_t)(BASE_DEBUG_ADDRESS + debug_count++));
#endif
                // magic file has been written. may be a command
                index = find_magic_index(block);
                if (index == -1) {
#ifdef SE3_DEBUG_SD
                	uint8_t debug_buffer[512] = "[proto_recv] index = 0xFF, forwarding write operation\n\0";
                	MYPRINTF(debug_buffer,(uint32_t)(BASE_DEBUG_ADDRESS + debug_count++));
#endif
                    // block is not a request. forward
                    r = se3_storage_range_add(&range, lun, (uint8_t*)data, block, range_write);
                    if (SE3_PROTO_OK != r)
                    {
#ifdef SE3_DEBUG_SD
                    	uint8_t debug_buffer[512] = "[proto_recv] Error writing in SD card\n\0";
                    	MYPRINTF(debug_buffer,(uint32_t)(BASE_DEBUG_ADDRESS + debug_count++));
#endif
                    	return r;
                    }
                }
                else {
                    // block is a request
                    if (comm.req_ready) {
                        // already processing request. ignore
#ifdef SE3_DEBUG_SD
                    	uint8_t debug_buffer[512] = "[proto_recv] comm.req_ready is true, ignoring request\n\0";
                    	MYPRINTF(debug_buffer,(uint32_t)(BASE_DEBUG_ADDRESS + debug_count++));
#endif

                        SE3_TRACE(("P W%02u request already fully received", (unsigned)index));
                        continue;
                    }
                    else {
#ifdef SE3_DEBUG_SD
                    	uint8_t debug_buffer[512] = "[proto_recv] comm.req_ready is false, handling request\n\0";
                    	MYPRINTF(debug_buffer,(uint32_t)(BASE_DEBUG_ADDRESS + debug_count++));
#endif
                        handle_req_recv(index, data);
                    }
                }
            }
        }
//			r = se3_storage_range_add(&range, lun, (uint8_t*)data, block, range_write);
//			if (SE3_PROTO_OK != r) return r;
	}
	data += SE3_COMM_BLOCK;
}

//flush any remaining block
#ifdef SE3_DEBUG_SD
uint8_t debug_buffer_main[512] = "[proto_recv] Flushing any remaining blocks\n\0";
MYPRINTF(debug_buffer_main,(uint32_t)(BASE_DEBUG_ADDRESS + debug_count++));
#endif
return se3_storage_range_add(&range, lun, NULL, 0xFFFFFFFF, range_write);
}

int32_t se3_proto_send(uint8_t lun, uint8_t* buf, uint32_t blk_addr, uint16_t blk_len)
{
	int32_t r = SE3_PROTO_OK;
	uint32_t block;
	int index;
	uint8_t* data = buf;
	s3_storage_range range = {
		.first = 0,
		.count = 0
	};

	for (block = blk_addr; block < blk_addr + blk_len; block++) {
		if(block==0) {
            // forward
			if (r == SE3_PROTO_OK) r = se3_storage_range_add(&range, lun, data, block, range_read);
		}
		else{
			index = find_magic_index(block);
            if (index == -1) {
                // forward
                if (r == SE3_PROTO_OK) r = se3_storage_range_add(&range, lun, data, block, range_read);
            }
            else {
                handle_resp_send(index, data);
            }
		}
		data += SE3_COMM_BLOCK;
	}

	//flush any remaining block
    if (r == SE3_PROTO_OK) r = se3_storage_range_add(&range, lun, NULL, 0xFFFFFFFF, range_read);
    return r;
}

bool block_is_magic(const uint8_t* buf)
{
	const uint8_t* a = buf;
	const uint8_t* b = se3_magic;
	size_t i;
	for (i = 0; i < SE3_COMM_BLOCK / SE3_MAGIC_SIZE - 1; i++) {
		if (memcmp(a, b, SE3_MAGIC_SIZE))return false;
        a += SE3_MAGIC_SIZE;
	}
	if (buf[SE3_COMM_BLOCK - 1] >= SE3_COMM_N)return false;
	return true;
}

int find_magic_index(uint32_t block)
{
	int i; size_t k;
	for (i = 0, k = comm.block_guess; i < SE3_COMM_N; i++, k = (k+1)%(SE3_COMM_N) ) {
		if (block == comm.blocks[i]) {
			comm.block_guess = (size_t)((i + 1) % 16);
			return i;
		}
	}
	return -1;
}

int32_t se3_storage_range_add(s3_storage_range* range, uint8_t lun, uint8_t* buf, uint32_t block, uint32_t direction)
{
	bool ret = true;
	if (range->count == 0) {
		range->buf = buf;
		range->first = block;
		range->count = 1;
	}
	else {
		if (block == range->first + range->count) {
			range->count++;
		}
		else {
			if (direction == range_write){
				ret = secube_sdio_write(lun, range->buf, range->first, range->count);
				SE3_TRACE(("%i: write buf=%u count=%u to block=%u", ret, (unsigned)range->buf, range->count, range->first));
			}
			else {
				ret = secube_sdio_read(lun, range->buf, range->first, range->count);
				SE3_TRACE(("%d: read buf=%u count=%u from block=%u", ret, (unsigned)range->buf, range->count, range->first));
			}
			range->count = 0;
		}
	}

	return (ret)?(SE3_PROTO_OK):(SE3_PROTO_FAIL);
}

void handle_req_recv(int index, const uint8_t* blockdata)
{
    uint16_t nblocks;
    if (index == SE3_COMM_N - 1) {
        SE3_TRACE(("P data write to block %d ignored", index));
        return;
    }

    comm.resp_ready = false;

    if (index == 0) {
        // REQ block
#ifdef SE3_DEBUG_SD
        uint8_t debug_buffer[512] = "[handle_req_recv]  Index = 0\n\0";
        MYPRINTF(debug_buffer,(uint32_t)(BASE_DEBUG_ADDRESS + debug_count++));
#endif
        // read and decode header
        memcpy(comm.req_hdr, blockdata, SE3_REQ_SIZE_HEADER);
        SE3_GET16(comm.req_hdr, SE3_REQ_OFFSET_CMD, req_hdr.cmd);
        SE3_GET16(comm.req_hdr, SE3_REQ_OFFSET_CMDFLAGS, req_hdr.cmd_flags);
        SE3_GET16(comm.req_hdr, SE3_REQ_OFFSET_LEN, req_hdr.len);
        SE3_GET32(comm.req_hdr, SE3_REQ_OFFSET_CMDTOKEN, req_hdr.cmdtok[0]);
#if SE3_CONF_CRC
		SE3_GET16(comm.req_hdr, SE3_REQ_OFFSET_CRC, req_hdr->crc);
#endif
        // read data
        memcpy(comm.req_data, blockdata + SE3_REQ_SIZE_HEADER, SE3_COMM_BLOCK - SE3_REQ_SIZE_HEADER);

        nblocks = req_hdr.len / SE3_COMM_BLOCK;
        if (req_hdr.len%SE3_COMM_BLOCK != 0) {
            nblocks++;
        }
        if (nblocks > SE3_COMM_N - 1) {
            resp_hdr.status = SE3_ERR_COMM;
            comm.req_bmap = 0;
            comm.resp_ready = true;
        }
        // update bit map
        comm.req_bmap &= SE3_BMAP_MAKE(nblocks);
        SE3_BIT_CLEAR(comm.req_bmap, 0);
    }
    else {
		#ifdef SE3_DEBUG_SD
				uint8_t debug_buffer1[512] = "[handle_req_recv]  Index != 0\n\0";
				MYPRINTF(debug_buffer1,(uint32_t)(BASE_DEBUG_ADDRESS + debug_count++));
		#endif
        // REQDATA block
        // read header
        SE3_GET32(blockdata, SE3_REQDATA_OFFSET_CMDTOKEN, req_hdr.cmdtok[index]);
        // read data
        memcpy(
            comm.req_data + 1 * (SE3_COMM_BLOCK - SE3_REQ_SIZE_HEADER) + (index - 1)*(SE3_COMM_BLOCK - SE3_REQDATA_SIZE_HEADER),
            blockdata + SE3_REQDATA_SIZE_HEADER,
            SE3_COMM_BLOCK - SE3_REQDATA_SIZE_HEADER);
        SE3_GET32(blockdata, 0, req_hdr.cmdtok[index]);
        // update bit map
        SE3_BIT_CLEAR(comm.req_bmap, index);
    }

    if (comm.req_bmap == 0) {
#ifdef SE3_DEBUG_SD
        uint8_t debug_buffer2[512] = "[handle_req_recv]  Ready to execute\n\0";
        MYPRINTF(debug_buffer2,(uint32_t)(BASE_DEBUG_ADDRESS + debug_count++));
#endif
        comm.req_ready = true;
        comm.req_bmap = SE3_BMAP_MAKE(32);
        comm.block_guess = 0;
    }
}

void handle_resp_send(int index, uint8_t* blockdata)
{
    uint16_t u16tmp;

    if (index == SE3_COMM_N - 1) {
        // discover
        memcpy(blockdata + SE3_DISCO_OFFSET_MAGIC, se3_magic + SE3_MAGIC_SIZE / 2, SE3_MAGIC_SIZE / 2);
        memcpy(blockdata + SE3_DISCO_OFFSET_MAGIC + SE3_MAGIC_SIZE / 2, se3_magic, SE3_MAGIC_SIZE / 2);
        memcpy(blockdata + SE3_DISCO_OFFSET_SERIAL, serial.data, SE3_SERIAL_SIZE);
        memcpy(blockdata + SE3_DISCO_OFFSET_HELLO, se3_hello, SE3_HELLO_SIZE);
        u16tmp = (comm.locked) ? (1) : (0);
        SE3_SET16(blockdata, SE3_DISCO_OFFSET_STATUS, u16tmp);
    }
    else {
        if (comm.resp_ready) {
            // response ready
            if (SE3_BIT_TEST(comm.resp_bmap, index)) {
                // read valid block
                if (index == 0) {
                    // RESP block

                    // encode and write header
                    u16tmp = 1;
                    SE3_SET16(comm.resp_hdr, SE3_RESP_OFFSET_READY, u16tmp);
                    SE3_SET16(comm.resp_hdr, SE3_RESP_OFFSET_STATUS, resp_hdr.status);
                    SE3_SET16(comm.resp_hdr, SE3_RESP_OFFSET_LEN, resp_hdr.len);
                    SE3_SET32(comm.resp_hdr, SE3_RESP_OFFSET_CMDTOKEN, resp_hdr.cmdtok[0]);
#if SE3_CONF_CRC
                    SE3_SET16(comm.resp_hdr, SE3_RESP_OFFSET_CRC, resp_hdr.crc);
#endif
                    memcpy(blockdata, comm.resp_hdr, SE3_RESP_SIZE_HEADER);

                    // write data
                    memcpy(blockdata + SE3_RESP_SIZE_HEADER, comm.resp_data, SE3_COMM_BLOCK - SE3_RESP_SIZE_HEADER);
                }
                else {
                    // RESPDATA block
                    // write header
                    SE3_SET32(blockdata, SE3_RESPDATA_OFFSET_CMDTOKEN, resp_hdr.cmdtok[index]);
                    // write data
                    memcpy(
                        blockdata + SE3_RESPDATA_SIZE_HEADER,
                        comm.resp_data + 1 * (SE3_COMM_BLOCK - SE3_RESP_SIZE_HEADER) + (index - 1)*(SE3_COMM_BLOCK - SE3_RESPDATA_SIZE_HEADER),
                        SE3_COMM_BLOCK - SE3_RESPDATA_SIZE_HEADER);
                }
            }
            else {
                // read invalid block
                memset(blockdata, 0, SE3_COMM_BLOCK);
            }
        }
        else {
            // response not ready
            memset(blockdata, SE3_RESP_OFFSET_READY, sizeof(uint16_t));
        }
    }
}
