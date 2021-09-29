/*
 * nbcrypt.h
 *
 *  Created on: 27/09/2021
 *      Author: Anti
 */

#ifndef NBCRYPT_H_
#define NBCRYPT_H_

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include <stddef.h>
#include <stdint.h>
typedef struct nbcdata_t* nbcdata;

nbcdata nbc_init(const uint8_t bName[16]);
uint8_t* nbc_decrypt(nbcdata, const uint8_t *, size_t);
uint8_t* nbc_encrypt(nbcdata, const uint8_t *, size_t);
void nbc_data_free(uint8_t**);

void nbc_free(nbcdata);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* NBCRYPT_H_ */

