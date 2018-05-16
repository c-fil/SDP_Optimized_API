#include "se3_comm_core.h"



SE3_FLASH_INFO flash;
SE3_COMM_STATUS *comm; //pointer to se3_core structure
req_header* req_hdr;
resp_header* resp_hdr;
SE3_SERIAL* serial;

const uint8_t se3_hello[SE3_HELLO_SIZE] = {
	'H', 'e', 'l', 'l', 'o', ' ', 'S', 'E',
    'c', 'u', 'b', 'e', 0, 0, 0, 0,
    0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0
};

void se3_communication_init(SE3_COMM_STATUS* comm_ref, req_header * req_hdr_comm,
		resp_header* resp_hdr_comm, SE3_SERIAL* serial_comm){
	req_hdr = req_hdr_comm;
	resp_hdr = resp_hdr_comm;
	serial = serial_comm;
	comm = comm_ref;
    memset(comm_ref, 0, sizeof(SE3_COMM_STATUS));
    memset(&flash, 0, sizeof(SE3_FLASH_INFO));
//TODO: MEMSET DI QUALSIASI COSA
    //comm.req_hdr = se3_comm_request_buffer;
    comm->req_hdr = malloc(SE3_COMM_N*SE3_COMM_BLOCK * sizeof (uint8_t));
    //comm.req_data = se3_comm_request_buffer + SE3_REQ_SIZE_HEADER;
    comm->req_data =  comm->req_hdr + SE3_REQ_SIZE_HEADER;
    //comm.resp_hdr = se3_comm_response_buffer;
    comm->resp_hdr = malloc(SE3_COMM_N*SE3_COMM_BLOCK * sizeof (uint8_t));
    //comm.resp_data = se3_comm_response_buffer + SE3_RESP_SIZE_HEADER;
    comm->resp_data =  comm->resp_hdr + SE3_RESP_SIZE_HEADER;

    comm->magic_bmap = SE3_BMAP_MAKE(16); //set 16 LSB bit to 1
    comm->magic_ready = false;
    comm->req_bmap = SE3_BMAP_MAKE(1); //LSB set to 1
    comm->locked = false;
    comm->req_ready = false;
    comm->req_bmap = SE3_BMAP_MAKE(32);
    comm->resp_ready = true;
    comm->resp_bmap = 0;
	se3_flash_init();
}

//TODO:fa schifo perche' comm e' gigante e lui non pulisce niente
void se3_proto_request_reset()
{
    comm->req_ready = false;
    comm->req_bmap = SE3_BMAP_MAKE(32);
}

int32_t se3_proto_recv(uint8_t lun, const uint8_t* buf, uint32_t blk_addr, uint16_t blk_len)
{
	int32_t r = SE3_PROTO_OK;
	uint32_t block;
	int index;
	const uint8_t* data = buf;
    //uint16_t u16tmp;

	s3_storage_range range = {
		.first = 0,
		.count = 0
	};

	for (block = blk_addr; block < blk_addr + blk_len; block++) {
		if (block == 0) {
			r = se3_storage_range_add(&range, lun, (uint8_t*)data, block, range_write);
			if (SE3_PROTO_OK != r) return r;
		}
		else {
            if (block_is_magic(data)) {
                // magic block
                if (comm->locked) {
                    // if locked, prevent initialization
                    continue;
                }
                if (comm->magic_ready) {
                    // if magic already initialized, reset
                    comm->magic_ready = false;
                    comm->magic_bmap = SE3_BMAP_MAKE(16);
                    for (index = 0; index < 16; index++)
                        comm->blocks[index] = 0;
                }
                // store block in blocks map
                index = data[SE3_COMM_BLOCK - 1];
                comm->blocks[index] = block;
                SE3_BIT_CLEAR(comm->magic_bmap, index);
                if (comm->magic_bmap == 0) {
                    comm->magic_ready = true;
                }
            }
            else{
                // not a magic block
                if (!comm->magic_ready) {
                    // magic file has not been written yet. forward
                    r = se3_storage_range_add(&range, lun, (uint8_t*)data, block, range_write);
                    if (SE3_PROTO_OK != r) return r;
                }
                else {
                    // magic file has been written. may be a command
                    index = find_magic_index(block);
                    if (index == -1) {
                        // block is not a request. forward
                        r = se3_storage_range_add(&range, lun, (uint8_t*)data, block, range_write);
                        if (SE3_PROTO_OK != r) return r;
                    }
                    else {
                        // block is a request
                        if (comm->req_ready) {
                            // already processing request. ignore
                            SE3_TRACE(("P W%02u request already fully received", (unsigned)index));
                            continue;
                        }
                        else {
                            handle_req_recv(index, data);
                        }
                    }
                }
            }
		}
		data += SE3_COMM_BLOCK;
	}

	//flush any remaining block
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
	for (i = 0, k = comm->block_guess; i < SE3_COMM_N; i++, k = (k+1)%(SE3_COMM_N) ) {
		if (block == comm->blocks[i]) {
			comm->block_guess = (size_t)((i + 1) % 16);
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

    comm->resp_ready = false;

    if (index == 0) {
        // REQ block

        // read and decode header
        memcpy(comm->req_hdr, blockdata, SE3_REQ_SIZE_HEADER);
        SE3_GET16(comm->req_hdr, SE3_REQ_OFFSET_CMD, req_hdr->cmd);
        SE3_GET16(comm->req_hdr, SE3_REQ_OFFSET_CMDFLAGS, req_hdr->cmd_flags);
        SE3_GET16(comm->req_hdr, SE3_REQ_OFFSET_LEN, req_hdr->len);
        SE3_GET32(comm->req_hdr, SE3_REQ_OFFSET_CMDTOKEN, req_hdr->cmdtok[0]);
#if SE3_CONF_CRC
		SE3_GET16(comm->req_hdr, SE3_REQ_OFFSET_CRC, req_hdr->crc);
#endif
        // read data
        memcpy(comm->req_data, blockdata + SE3_REQ_SIZE_HEADER, SE3_COMM_BLOCK - SE3_REQ_SIZE_HEADER);

        nblocks = req_hdr->len / SE3_COMM_BLOCK;
        if (req_hdr->len%SE3_COMM_BLOCK != 0) {
            nblocks++;
        }
        if (nblocks > SE3_COMM_N - 1) {
            resp_hdr->status = SE3_ERR_COMM;
            comm->req_bmap = 0;
            comm->resp_ready = true;
        }
        // update bit map
        comm->req_bmap &= SE3_BMAP_MAKE(nblocks);
        SE3_BIT_CLEAR(comm->req_bmap, 0);
    }
    else {
        // REQDATA block
        // read header
        SE3_GET32(blockdata, SE3_REQDATA_OFFSET_CMDTOKEN, req_hdr->cmdtok[index]);
        // read data
        memcpy(
            comm->req_data + 1 * (SE3_COMM_BLOCK - SE3_REQ_SIZE_HEADER) + (index - 1)*(SE3_COMM_BLOCK - SE3_REQDATA_SIZE_HEADER),
            blockdata + SE3_REQDATA_SIZE_HEADER,
            SE3_COMM_BLOCK - SE3_REQDATA_SIZE_HEADER);
        SE3_GET32(blockdata, 0, req_hdr->cmdtok[index]);
        // update bit map
        SE3_BIT_CLEAR(comm->req_bmap, index);
    }

    if (comm->req_bmap == 0) {
        comm->req_ready = true;
        comm->req_bmap = SE3_BMAP_MAKE(32);
        comm->block_guess = 0;
    }
}

void handle_resp_send(int index, uint8_t* blockdata)
{
    uint16_t u16tmp;

    if (index == SE3_COMM_N - 1) {
        // discover
        memcpy(blockdata + SE3_DISCO_OFFSET_MAGIC, se3_magic + SE3_MAGIC_SIZE / 2, SE3_MAGIC_SIZE / 2);
        memcpy(blockdata + SE3_DISCO_OFFSET_MAGIC + SE3_MAGIC_SIZE / 2, se3_magic, SE3_MAGIC_SIZE / 2);
        memcpy(blockdata + SE3_DISCO_OFFSET_SERIAL, serial->data, SE3_SERIAL_SIZE);
        memcpy(blockdata + SE3_DISCO_OFFSET_HELLO, se3_hello, SE3_HELLO_SIZE);
        u16tmp = (comm->locked) ? (1) : (0);
        SE3_SET16(blockdata, SE3_DISCO_OFFSET_STATUS, u16tmp);
    }
    else {
        if (comm->resp_ready) {
            // response ready
            if (SE3_BIT_TEST(comm->resp_bmap, index)) {
                // read valid block
                if (index == 0) {
                    // RESP block

                    // encode and write header
                    u16tmp = 1;
                    SE3_SET16(comm->resp_hdr, SE3_RESP_OFFSET_READY, u16tmp);
                    SE3_SET16(comm->resp_hdr, SE3_RESP_OFFSET_STATUS, resp_hdr->status);
                    SE3_SET16(comm->resp_hdr, SE3_RESP_OFFSET_LEN, resp_hdr->len);
                    SE3_SET32(comm->resp_hdr, SE3_RESP_OFFSET_CMDTOKEN, resp_hdr->cmdtok[0]);
#if SE3_CONF_CRC
                    SE3_SET16(comm->resp_hdr, SE3_RESP_OFFSET_CRC, resp_hdr->crc);
#endif
                    memcpy(blockdata, comm->resp_hdr, SE3_RESP_SIZE_HEADER);

                    // write data
                    memcpy(blockdata + SE3_RESP_SIZE_HEADER, comm->resp_data, SE3_COMM_BLOCK - SE3_RESP_SIZE_HEADER);
                }
                else {
                    // RESPDATA block
                    // write header
                    SE3_SET32(blockdata, SE3_RESPDATA_OFFSET_CMDTOKEN, resp_hdr->cmdtok[index]);
                    // write data
                    memcpy(
                        blockdata + SE3_RESPDATA_SIZE_HEADER,
                        comm->resp_data + 1 * (SE3_COMM_BLOCK - SE3_RESP_SIZE_HEADER) + (index - 1)*(SE3_COMM_BLOCK - SE3_RESPDATA_SIZE_HEADER),
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

//FLASH MEMORY FUNCTIONS

bool flash_swap()
{
	uint32_t other;
	uint32_t other_base;
	uint32_t other_index;
	size_t other_used;
	size_t other_pos;

	size_t n;
	bool success, b;
	se3_flash_it it;
	if (flash.sector == SE3_FLASH_S0) {
		other = SE3_FLASH_S1;
		other_base = SE3_FLASH_S1_ADDR;
	}
	else if (flash.sector == SE3_FLASH_S1) {
		other = SE3_FLASH_S0;
		other_base = SE3_FLASH_S0_ADDR;
	}
	else {
		return false;
	}
	other_index = other_base + SE3_FLASH_MAGIC_SIZE;
	//erase other sector
	flash_erase(other);
	//zero non-programmed slots in index table (first_free_pos to end)
	if (flash.first_free_pos < SE3_FLASH_INDEX_SIZE) {
		n = SE3_FLASH_INDEX_SIZE - flash.first_free_pos;
		flash_zero((uint32_t)flash.index + flash.first_free_pos, n);
	}

	//copy good blocks to other sector
	success = true;
	other_used = SE3_FLASH_MAGIC_SIZE + SE3_FLASH_INDEX_SIZE;
	other_pos = 0;
	se3_flash_it_init(&it);
	while (se3_flash_it_next(&it)) {
		if (it.type != SE3_FLASH_TYPE_INVALID) {
			//copy data
			b = flash_program(
				other_base + other_used,
				flash.data + it.pos*SE3_FLASH_BLOCK_SIZE,
				it.blocks*SE3_FLASH_BLOCK_SIZE
			);
			if (!b) {
				success = false; break;
			}

			//write index
			b = flash_program(other_index + other_pos, &(it.type), 1);
			if (!b) {
				success = false; break;
			}
			if (it.blocks > 1) {
				b = flash_fill(other_index + other_pos + 1, 0xFE, it.blocks - 1);
				if (!b) {
					success = false; break;
				}
			}

			other_used += it.blocks*SE3_FLASH_BLOCK_SIZE;
			other_pos += it.blocks;
		}
	}
	if (!success) {
		return false;
	}

	//write magic to other sector
	if (!flash_program(other_base, se3_magic, SE3_FLASH_MAGIC_SIZE)) {
		return false;
	}

	//clear magic from this sector
	if (!flash_zero((uint32_t)flash.base, 1)) {
		return false;
	}

	//swap sectors
	flash.base = (uint8_t*)other_base;
    flash.sector = other;
    flash.index = flash.base + SE3_FLASH_MAGIC_SIZE;
    flash.data = flash.index + SE3_FLASH_INDEX_SIZE;
    flash.allocated = flash.used = other_used;
    flash.first_free_pos = other_pos;

	return true;
}

void se3_flash_info_setup(uint32_t sector, const uint8_t* base)
{
	flash.base = base;
    flash.sector = sector;
    flash.index = flash.base + SE3_FLASH_MAGIC_SIZE;
    flash.data = flash.index + SE3_FLASH_INDEX_SIZE;
    flash.allocated = flash.used = SE3_FLASH_MAGIC_SIZE + SE3_FLASH_INDEX_SIZE;
    flash.first_free_pos = 0;
}

bool se3_flash_canfit(size_t size)
{
	size_t size_on_flash = size + 2;
	return (size_on_flash <= (SE3_FLASH_SECTOR_SIZE - flash.used));
}

bool se3_flash_init()
{
	se3_flash_it it;
	uint8_t* base;
	uint32_t sector;
	//uint16_t record_key;

	// check for flash magic
	bool magic0 = !memcmp((void*)SE3_FLASH_S0_ADDR, se3_magic, SE3_FLASH_MAGIC_SIZE);
	bool magic1 = !memcmp((void*)SE3_FLASH_S1_ADDR, se3_magic, SE3_FLASH_MAGIC_SIZE);

	//choose active sector
	if (magic0 && magic1) {
		//both marked, the one with last index programmed should be deleted
		if (0xFF == *((uint8_t*)(SE3_FLASH_S1_ADDR + SE3_FLASH_MAGIC_SIZE + SE3_FLASH_INDEX_SIZE - 1))){
			magic0 = false;
			flash_zero(SE3_FLASH_S0_ADDR, 1);
		}
		else {
			magic1 = false;
			flash_zero(SE3_FLASH_S1_ADDR, 1);
		}
	}

	if (magic0) {
		base = (uint8_t*)SE3_FLASH_S0_ADDR;
		sector = SE3_FLASH_S0;
	}
	else if (magic1) {
		base = (uint8_t*)SE3_FLASH_S1_ADDR;
		sector = SE3_FLASH_S1;
	}
	else {
		// initialize S0 as active sector
		flash_erase(SE3_FLASH_S0);
		flash_program(SE3_FLASH_S0_ADDR, se3_magic, SE3_FLASH_MAGIC_SIZE);
		base = (uint8_t*)SE3_FLASH_S0_ADDR;
		sector = SE3_FLASH_S0;
	}
	se3_flash_info_setup(sector, base);

	//scan flash
	se3_flash_it_init(&it);
	while (se3_flash_it_next(&it)) {
		flash.allocated += it.blocks*SE3_FLASH_BLOCK_SIZE;
		if (it.type != 0) {
			flash.used += it.blocks*SE3_FLASH_BLOCK_SIZE;
            if (it.type == SE3_FLASH_TYPE_SERIAL) {
                memcpy(serial->data, it.addr, SE3_SERIAL_SIZE);
                serial->written = true;
            }
		}
	}
	if (it.pos > SE3_FLASH_INDEX_SIZE) {
		it.pos = SE3_FLASH_INDEX_SIZE;
	}
	flash.first_free_pos = it.pos;

	return true;
}

bool se3_flash_it_write(se3_flash_it* it, uint16_t off, const uint8_t* data, uint16_t size)
{
	if (off + size > 2 + it->size)return false;
    return flash_program((uint32_t)it->addr + off, data, size);
}

void se3_flash_it_init(se3_flash_it* it)
{
	it->addr = NULL;
}

bool se3_flash_it_next(se3_flash_it* it)
{
	uint8_t type;
	const uint8_t* node;
	size_t pos2;
	if (it->addr == NULL) {
		it->pos = 0;
		it->addr = flash.data + 2;
	}
	else {
		(it->pos)+=it->blocks;
	}
	while (it->pos < SE3_FLASH_INDEX_SIZE) {
		type = *(flash.index + it->pos);
		if (type == 0xFF) return false;
		if (type != 0xFE) {
			node = flash.data + (it->pos) * SE3_FLASH_BLOCK_SIZE;
			it->addr = node + 2;
            SE3_GET16(node, 0, it->size);
			it->type = type;

			//count 'CONT' nodes after
			pos2 = it->pos + 1;
			while (pos2 < SE3_FLASH_INDEX_SIZE && *(flash.index + pos2) == 0xFE)pos2++;
			it->blocks = (uint16_t)(pos2 - it->pos);
			return true;
		}
		(it->pos)++;
	}
	return false;
}

size_t se3_flash_unused()
{
	return SE3_FLASH_SECTOR_SIZE - flash.used;
}

bool se3_flash_it_new(se3_flash_it* it, uint8_t type, uint16_t size)
{
	size_t pos, nblocks;
	const uint8_t* node;
	size_t avail = SE3_FLASH_SECTOR_SIZE - flash.allocated;
	uint16_t size_on_flash = size + 2;
	if (size_on_flash > SE3_FLASH_NODE_MAX)return false;
	if (size_on_flash > (SE3_FLASH_SECTOR_SIZE - flash.used)) {
		return false;
	}
	if (size_on_flash > avail) {
		// swap sector
		if (!flash_swap()) {
			return false;
		}
	}
	if (flash.first_free_pos >= SE3_FLASH_INDEX_SIZE) {
		return false;
	}
	pos = flash.first_free_pos;
	node = flash.data + pos*SE3_FLASH_BLOCK_SIZE;

	nblocks = size_on_flash / SE3_FLASH_BLOCK_SIZE;
	if (size_on_flash % SE3_FLASH_BLOCK_SIZE)nblocks++;
	if (!flash_program((uint32_t)flash.index + pos, &type, 1)) {
		return false;
	}
	flash.first_free_pos += 1;
	if (nblocks > 1) {
		if (!flash_fill((uint32_t)flash.index + pos + 1, 0xFE, nblocks - 1)) {
			return false;
		}
		flash.first_free_pos += nblocks - 1;
	}

	if (!flash_program((uint32_t)node, (uint8_t*)&size, 2)) {
		return false;
	}
	it->addr = node + 2;
	it->pos = pos;
	it->size = size;
	it->type = type;
	it->blocks = (uint16_t)nblocks;

	flash.used += nblocks*SE3_FLASH_BLOCK_SIZE;
	flash.allocated += nblocks*SE3_FLASH_BLOCK_SIZE;

	return true;
}

bool se3_flash_pos_delete(size_t pos)
{
	size_t pos2, blocks;
	if (pos >= SE3_FLASH_INDEX_SIZE)return false;
	pos2 = pos + 1;
	while (pos2 < SE3_FLASH_INDEX_SIZE && *(flash.index + pos2) == 0xFE)pos2++;
	blocks = (pos2 - pos);
	if (pos + blocks > SE3_FLASH_INDEX_SIZE)return false;
	if (!flash_zero((uint32_t)flash.index + pos, blocks)) {
		return false;
	}
	flash.used -= blocks*SE3_FLASH_BLOCK_SIZE;
	return true;
}

bool se3_flash_it_delete(se3_flash_it* it)
{
	if (it->pos + it->blocks > SE3_FLASH_INDEX_SIZE) {
		return false;
	}
	if (!flash_zero((uint32_t)flash.index + it->pos, it->blocks)) {
		return false;
	}
	flash.used -= it->blocks*SE3_FLASH_BLOCK_SIZE;
	return true;
}

bool se3_flash_bootmode_reset(uint32_t addr, size_t size){
	return flash_zero(addr, size);
}
