/** \brief structure holding host-device communication status and buffers
 *
 *  req_ready and resp_ready must be volatile, otherwise -O3 optimization will not work.
 */
extern SE3_FLASH_INFO flash;
SE3_COMM_STATUS comm;

typedef struct SE3_COMM_STATUS_ {
    // magic
    bool magic_ready;  ///< magic written flag
    uint32_t magic_bmap;  ///< bit map of written magic sectors
    // block map
    uint32_t blocks[SE3_COMM_N];  ///< map of blocks
    uint32_t block_guess;  ///< guess for next block that will be accessed
    bool locked;  ///< prevent magic initialization

    // request
    volatile bool req_ready;  ///< request ready flag
    uint32_t req_bmap;  ///< map of received request blocks
    uint8_t* req_data;  ///< received data buffer
    uint8_t* req_hdr;   ///< received header buffer

    // response
    volatile bool resp_ready;  ///< response ready flag
    uint32_t resp_bmap;  ///< map of sent response blocks
    uint8_t* resp_data;  ///< buffer for data to be sent
    uint8_t* resp_hdr;  ///< buffer for header to be sent
} SE3_COMM_STATUS;

/** \brief Flash management structure */
typedef struct SE3_FLASH_INFO_ {
    uint32_t sector;  ///< active sector number
    const uint8_t* base;
    const uint8_t* index;
    const uint8_t* data;
    size_t first_free_pos;
    size_t used;
    size_t allocated;
} SE3_FLASH_INFO;
