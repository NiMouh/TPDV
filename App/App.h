#ifndef _APP_H_
#define _APP_H_

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>

#include "sgx_error.h"       /* sgx_status_t */
#include "sgx_eid.h"     /* sgx_enclave_id_t */
#include "sgx_dh.h"

#define ENCLAVE1_FILENAME "enclave1.signed.so"
#define ENCLAVE2_FILENAME "enclave2.signed.so"

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

static bool read_file_to_buf(const char *filename, uint8_t *buf, uint32_t bsize);
static bool write_buf_to_file(const uint8_t *filename, const uint8_t *buf, uint32_t bsize, long offset);

uint8_t *sha256_hash(const uint8_t *data, uint32_t data_len);

int create_tpdv(const uint8_t *filename,const uint32_t filename_size,const uint8_t *password,const uint32_t password_size,const uint8_t *creator,const uint32_t creator_size);
int list_all_assets2(const uint8_t *filename, const uint8_t *password);
int list_all_assets(const uint8_t *sealed_data, uint32_t sealed_size);
int retrieve_asset(const uint8_t *filename, const uint8_t *password, const uint8_t *asset_filename);
int change_password(const uint8_t *filename, const uint8_t *old_password, const uint8_t *new_password);
int check_asset_integrity(const uint8_t *filename, const uint8_t *password, const uint8_t *asset_filename);
int clone_tpdv(const uint8_t *original_tpdv, const uint8_t *original_password, const uint8_t *cloned_tpdv, const uint8_t *cloned_password);
int add_asset(const uint8_t *filename, const uint8_t *password, const uint8_t *asset_filename);


#if defined(__cplusplus)
}
#endif

#endif /* !_APP_H_ */
