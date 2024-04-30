#ifndef _APP_H_
#define _APP_H_

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>

#include "sgx_error.h"       /* sgx_status_t */
#include "sgx_eid.h"     /* sgx_enclave_id_t */

#define ENCLAVE1_FILENAME "enclave1.signed.so"

/* Hashes */
#define SHA256_DIGEST_LENGTH 32

/* TPDV SIZES */
#define FILENAME_SIZE 20 // bytes
#define CREATOR_SIZE 20  // bytes
#define PASSWORD_SIZE 20 // bytes
#define NONCE_SIZE 4 // bytes
#define ASSETS_SIZE 4 // bytes
#define HEADER_SIZE (FILENAME_SIZE + CREATOR_SIZE + PASSWORD_SIZE + ASSETS_SIZE + NONCE_SIZE) // bytes
#define MAX_ASSETS 16000 // 16MB / 1KB = 16K assets

/* ASSET SIZES */
#define ASSETNAME_SIZE 20 // bytes



#if defined(__cplusplus)
extern "C" {
#endif

/**
 * @brief Create a new vault
 *
 * @details It takes a nonce (random int number), filename, password, creator and number of assets (0 in this case), saves them in a unsigned char array, seals it and saves it in a file.
 *
 * @param filename Vault filename
 * @param filename_size Vault filename size
 * @param password Vault password
 * @param password_size Vault password size
 * @param creator Vault creator
 * @param creator_size Vault creator size
 *
 * @return 0 if the vault was created successfully, 1 otherwise
 */
int create_tpdv(const uint8_t *filename,const uint32_t filename_size,const uint8_t *password,const uint32_t password_size,const uint8_t *creator,const uint32_t creator_size);



#if defined(__cplusplus)
}
#endif

#endif /* !_APP_H_ */
