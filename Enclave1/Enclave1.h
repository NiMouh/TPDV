#ifndef _ENCLAVE1_H_
#define _ENCLAVE1_H_

#include <stdlib.h>
#include <assert.h>
#include "sgx_dh.h"

#if defined(__cplusplus)
extern "C" {
#endif

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

int printf(const char *fmt, ...);


sgx_status_t seal(uint8_t* plaintext, uint32_t plaintext_len, sgx_sealed_data_t* sealed_data, uint32_t sealed_size);
sgx_status_t unseal(sgx_sealed_data_t* sealed_data, uint32_t sealed_size, uint8_t* plaintext, uint32_t plaintext_len);
uint32_t get_unsealed_data_size(uint8_t *sealed_data, uint32_t sealed_data_size);
uint32_t get_sealed_data_size(uint32_t plaintext_len);

void e1_init_session(sgx_status_t *dh_status);
void e1_generate_message1(sgx_dh_msg1_t *msg1,sgx_status_t *dh_status);
void e1_process_message2(const sgx_dh_msg2_t *msg2,sgx_dh_msg3_t *msg3,sgx_status_t *dh_status);
void e1_show_secret_key(void);

void e1_unseal_and_cipher(const uint8_t *sealed_data, uint32_t sealed_size, uint8_t *ciphertext, uint32_t ciphertext_size);

#if defined(__cplusplus)
}
#endif

#endif /* !_ENCLAVE1_H_ */
