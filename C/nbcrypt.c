//
//  NinebotCrypt
//
//  Created by Robert Trencheny on 2/23/20.
//  Copyright © 2020 Robert Trencheny. All rights reserved.
//  - C Port by Anti on 27/09/21

#include "nbcrypt.h"
#include <mbedtls/md.h>
#include <mbedtls/aes.h>

#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>

const uint8_t nbc_fw_data[16] = { 0x97, 0xCF, 0xB8, 0x02, 0x84, 0x41, 0x43, 0xDE, 0x56, 0x00, 0x2B, 0x3B, 0x34, 0x78, 0x0A, 0x5D };

struct nbcdata_t {
    uint8_t name_data[16];
    uint8_t ble_data [16];
    uint8_t app_data [16];
    uint8_t sha1_key [16];
    uint32_t msg_it;
    mbedtls_aes_context  aes_ctx;
    mbedtls_md_context_t sha_ctx;
};

#define nbc_log(a) (void)(a) // Ignore Logging
//#define nbc_log(a) printf(a "\n");


// Forward declare
void nbc_CryptoFirst        (nbcdata, uint8_t *, const uint8_t *src, size_t srcLength);
void nbc_CryptoNext         (nbcdata, uint8_t *, const uint8_t *src, size_t srcLength, uint32_t MsgIt);

uint16_t nbc_CalcCrcFirstMsg(nbcdata, const uint8_t *src, size_t srcLength);
uint32_t nbc_CalcCrcNextMsg (nbcdata, const uint8_t *src, size_t srcLength, uint32_t MsgIt);
void nbc_CalcSha1Key        (nbcdata, const uint8_t *key1, const uint8_t *key2);

void nbc_AesEcbEncrypt      (nbcdata, uint8_t* dst, const uint8_t* src, const uint8_t* key);
void nbc_Sha1               (nbcdata, uint8_t* dst, const uint8_t* src, const size_t srcLength);

void memxor(void*, const void*, const void*, size_t);


nbcdata nbc_init(const uint8_t bName[16]) {
	// TODO: take a uint8_t* name, strlen(name) then copy 16

	struct nbcdata_t * nbc = (struct nbcdata_t *)malloc(sizeof(struct nbcdata_t));
	memset(nbc, 0, sizeof(struct nbcdata_t));
	memcpy(nbc->name_data, bName, 16);

	mbedtls_md_init (&nbc->sha_ctx);
	mbedtls_md_setup(&nbc->sha_ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA1), 0);
	mbedtls_aes_init(&nbc->aes_ctx);

	nbc_CalcSha1Key(nbc, nbc->name_data, nbc_fw_data);

	return nbc;
}

void nbc_data_free(uint8_t**pData) {
	free(*pData);
	*pData = (void*)0;
}

void nbc_free(nbcdata nbc) {
	mbedtls_md_free (&nbc->sha_ctx);
	mbedtls_aes_free(&nbc->aes_ctx);
	free(nbc);
}

uint8_t * nbc_decrypt(nbcdata nbc, const uint8_t * src, size_t srcLength) {
	uint8_t * dst = (uint8_t*)malloc(srcLength - 6);
	memset(dst, 0  , srcLength - 6);
	memcpy(dst, src, 3);

	uint32_t new_msg_it = nbc->msg_it;
	if ((new_msg_it & 0x0008000) > 0 && (src[srcLength - 2] >> 7) == 0)
		new_msg_it += 0x0010000;

	new_msg_it = (new_msg_it & 0xFFFF0000)
			 + (uint32_t)(src[srcLength - 2] << 8)
			 + src[srcLength - 1];

	const size_t pLength = srcLength - 9;

	if (new_msg_it == 0) {
		nbc_CryptoFirst(nbc, dst+3, src+3, pLength);

		const uint8_t match[] = { 0x5A, 0xA5, 0x1E, 0x21, 0x3E, 0x5B };
		if (memcmp(dst, match, sizeof(match)) == 0) {
			nbc_log("Initial Key");
			memcpy(nbc->ble_data, dst + 7, 16);
			nbc_CalcSha1Key(nbc, nbc->name_data, nbc->ble_data);
		}

	} else {
		nbc_CryptoNext (nbc, dst+3, src+3, pLength, new_msg_it);

		const uint8_t match[] = { 0x5A, 0xA5, 0x00, 0x21, 0x3E, 0x5C, 0x01 };
		if (memcmp(dst, match, sizeof(match)) == 0) {
			nbc_log("Recalculate Key");
			nbc_CalcSha1Key(nbc, nbc->app_data, nbc->ble_data);
		}


		nbc->msg_it = new_msg_it;
	}

	return dst;
}

uint8_t * nbc_encrypt(nbcdata nbc, const uint8_t* src, size_t srcLength) {
	uint8_t *dst = (uint8_t *)malloc(srcLength+6);
	memset(dst, 0  , srcLength + 6);
	memcpy(dst, src, 3);
	size_t pLength = srcLength - 3;

	if (nbc->msg_it == 0){
		uint16_t crc = nbc_CalcCrcFirstMsg(nbc, src+3, pLength);
		nbc_CryptoFirst(nbc, dst+3, src+3, pLength);

		memset(dst + pLength + 3, 0, 6);
		memcpy(dst + pLength + 5, &crc, 2); // TODO: not so keen on this method
/*		dst[pLength + 3] = 0;
		dst[pLength + 4] = 0;
		dst[pLength + 5] = (uint8_t)((crc & 0x00FF)     );
		dst[pLength + 6] = (uint8_t)((crc & 0xFF00) >> 8);
		dst[pLength + 7] = 0;
		dst[pLength + 8] = 0;
*/
		++nbc->msg_it;
	} else {
		++nbc->msg_it;

		uint32_t crc = nbc_CalcCrcNextMsg(nbc, src  , pLength, nbc->msg_it);
		nbc_CryptoNext    (nbc, dst+3, src+3, pLength, nbc->msg_it);

		memcpy(dst + pLength + 3, &crc, 4);
		dst[pLength + 7] = (uint8_t)((nbc->msg_it & 0x0000FF00) >> 8);
		dst[pLength + 8] = (uint8_t)((nbc->msg_it & 0x000000FF) >> 0);

		const uint8_t match[] = { 0x5A, 0xA5, 0x10, 0x3E, 0x21, 0x5C, 0x00 };
		if (memcmp(src, match, sizeof(match)) == 0) {
			nbc_log("Save Key");
			memcpy(nbc->app_data, src + 7, 16);
		}

	}

	return dst;
}

void nbc_CryptoFirst(nbcdata nbc, uint8_t *dst, const uint8_t *src, size_t srcLength) {
	uint8_t aes_key[16];
	nbc_AesEcbEncrypt(nbc, aes_key, nbc_fw_data, nbc->sha1_key);

	size_t idx = 0;
	while (srcLength > 0) {
		size_t tmp_len = (srcLength <= 16) ? srcLength : 16;
		memxor(dst + idx, src + idx, aes_key, tmp_len);
		srcLength -= tmp_len;
		idx += tmp_len;
	}
}

void nbc_CryptoNext(nbcdata nbc, uint8_t * dst, const uint8_t * src, size_t srcLength, uint32_t MsgIt) {
	uint8_t aes_enc_data[16];
	aes_enc_data[ 0] = 1;
	aes_enc_data[ 1] = (uint8_t)((MsgIt & 0xFF000000) >> 24);
	aes_enc_data[ 2] = (uint8_t)((MsgIt & 0x00FF0000) >> 16);
	aes_enc_data[ 3] = (uint8_t)((MsgIt & 0x0000FF00) >>  8);
	aes_enc_data[ 4] = (uint8_t)((MsgIt & 0x000000FF) >>  0);
	aes_enc_data[ 5] = nbc->ble_data[0];
	aes_enc_data[ 6] = nbc->ble_data[1];
	aes_enc_data[ 7] = nbc->ble_data[2];
	aes_enc_data[ 8] = nbc->ble_data[3];
	aes_enc_data[ 9] = nbc->ble_data[4];
	aes_enc_data[10] = nbc->ble_data[5];
	aes_enc_data[11] = nbc->ble_data[6];
	aes_enc_data[12] = nbc->ble_data[7];
	aes_enc_data[13] = 0;
	aes_enc_data[14] = 0;
	aes_enc_data[15] = 0;

	size_t idx = 0;

	uint8_t aes_key[16];
	while (srcLength > 0) {
		++aes_enc_data[15];
		nbc_AesEcbEncrypt(nbc, aes_key, aes_enc_data, nbc->sha1_key);

		size_t tmp_len = (srcLength <= 16) ? srcLength : 16;
		memxor(dst + idx, src + idx, aes_key, tmp_len);
		srcLength  -= tmp_len;
		idx += tmp_len;
	}
}

uint16_t nbc_CalcCrcFirstMsg(nbcdata nbc, const uint8_t* src, size_t srcLength) {
	uint16_t ret = 0;

	for (size_t i = 0; i < srcLength; ++i)
		ret += src[i];
	ret = ret ^ 0xFFFF;

	uint8_t crc[2];
	crc[0] = (uint8_t)((ret & 0x00FF)     );
	crc[1] = (uint8_t)((ret & 0xFF00) >> 8);

	memcpy(&ret, crc, 2);
	return ret;
}

uint32_t nbc_CalcCrcNextMsg(nbcdata nbc, const uint8_t* src, size_t srcLength, uint32_t MsgIt) {
	uint8_t aes_enc_data[16];
	memset(aes_enc_data, 0, 16);

	aes_enc_data[ 0] = 89;
	aes_enc_data[ 1] = (uint8_t)((MsgIt & 0xFF000000) >> 24);
	aes_enc_data[ 2] = (uint8_t)((MsgIt & 0x00FF0000) >> 16);
	aes_enc_data[ 3] = (uint8_t)((MsgIt & 0x0000FF00) >> 8);
	aes_enc_data[ 4] = (uint8_t)((MsgIt & 0x000000FF) >> 0);
	aes_enc_data[ 5] = nbc->ble_data[0];
	aes_enc_data[ 6] = nbc->ble_data[1];
	aes_enc_data[ 7] = nbc->ble_data[2];
	aes_enc_data[ 8] = nbc->ble_data[3];
	aes_enc_data[ 9] = nbc->ble_data[4];
	aes_enc_data[10] = nbc->ble_data[5];
	aes_enc_data[11] = nbc->ble_data[6];
	aes_enc_data[12] = nbc->ble_data[7];
	aes_enc_data[13] = (uint8_t)(((srcLength - 3) & 0xFF0000) >> 16);
	aes_enc_data[14] = (uint8_t)(((srcLength - 3) & 0x00FF00) >>  8);
	aes_enc_data[15] = (uint8_t)(((srcLength - 3) & 0x0000FF) >>  0);

	uint8_t aes_key[16];
	nbc_AesEcbEncrypt(nbc, aes_key, aes_enc_data, nbc->sha1_key);

	uint8_t xor_data[16];
	memset(xor_data, 0, 16);
	memcpy(xor_data, src, 3);
	memxor(xor_data, xor_data, aes_key, 16);
	nbc_AesEcbEncrypt(nbc, aes_key, xor_data, nbc->sha1_key);

	srcLength -= 3;
	size_t idx = 3;
	while (srcLength > 0) {
		size_t tmp_len = (srcLength <= 16) ? srcLength : 16;

		memset(xor_data, 0, 16);
		memcpy(xor_data, src + idx, tmp_len);
		memxor(xor_data, xor_data, aes_key, 16);
		nbc_AesEcbEncrypt(nbc, aes_key, xor_data, nbc->sha1_key);

		srcLength -= tmp_len;
		idx += tmp_len;
	}

	aes_enc_data[0] = 1;
	aes_enc_data[15] = 0;

	uint8_t aes_key2[16];
	nbc_AesEcbEncrypt(nbc, aes_key2, aes_enc_data, nbc->sha1_key);

	uint32_t ret;
	memxor(&ret, aes_key2, aes_key, 4);

	return ret;
}

/* Takes two 16 byte parameters, saves to nbc.sha1_key */
void nbc_CalcSha1Key(nbcdata nbc, const uint8_t * data1, const uint8_t * data2) {
  uint8_t sha_data[32];
  memcpy(sha_data     , data1, 16);
  memcpy(sha_data + 16, data2, 16);

  uint8_t sha_hash[20];
  nbc_Sha1(nbc, sha_hash, sha_data, sizeof(sha_data));
  memcpy(nbc->sha1_key, sha_hash, 16);
}

/* Takes 16 bytes of Data and a 16 Byte Key, returns 16 bytes of encrypted */
void nbc_AesEcbEncrypt(nbcdata nbc, uint8_t* dst, const uint8_t* src, const uint8_t* key) {
	mbedtls_aes_setkey_enc(&nbc->aes_ctx, key, 128);
	mbedtls_aes_crypt_ecb (&nbc->aes_ctx, MBEDTLS_AES_ENCRYPT, src, dst);
}

/* Takes any length data, returns 20 bytes of Sha1 Key */
void nbc_Sha1(nbcdata nbc, uint8_t* dst, const uint8_t* src, const size_t srcLength) {
	mbedtls_md_starts(&nbc->sha_ctx);
	mbedtls_md_update(&nbc->sha_ctx, src, srcLength); // @suppress("Invalid arguments")
	mbedtls_md_finish(&nbc->sha_ctx, dst);
}

void memxor(void* dst, const void* src1, const void* src2, size_t length) {
  for (size_t idx = 0; idx < length; ++idx)
	((char*)dst)[idx] = (((char*)src1)[idx] ^ ((char*)src2)[idx]);
}
