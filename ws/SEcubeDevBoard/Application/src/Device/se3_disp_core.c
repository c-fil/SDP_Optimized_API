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
