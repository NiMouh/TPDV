#ifndef _ENCLAVE1_H_
#define _ENCLAVE1_H_

#include <stdlib.h>
#include <assert.h>

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

/**
 * @brief      Seals the plaintext given into the sgx_sealed_data_t structure
 *             given.
 *
 * @details    The plaintext can be any data. uint8_t is used to represent a
 *             byte. The sealed size can be determined by computing
 *             sizeof(sgx_sealed_data_t) + plaintext_len, since it is using
 *             AES-GCM which preserves length of plaintext. The size needs to be
 *             specified, otherwise SGX will assume the size to be just
 *             sizeof(sgx_sealed_data_t), not taking into account the sealed
 *             payload.
 *
 * @param      plaintext      The data to be sealed
 * @param[in]  plaintext_len  The plaintext length
 * @param      sealed_data    The pointer to the sealed data structure
 * @param[in]  sealed_size    The size of the sealed data structure supplied
 *
 * @return     Truthy if seal successful, falsy otherwise.
 */
sgx_status_t seal(uint8_t* plaintext, uint32_t plaintext_len, sgx_sealed_data_t* sealed_data, uint32_t sealed_size);

/**
 * @brief      Unseal the sealed_data given into c-string
 *
 * @details    The resulting plaintext is of type uint8_t to represent a byte.
 *             The sizes/length of pointers need to be specified, otherwise SGX
 *             will assume a count of 1 for all pointers.
 *
 * @param      sealed_data        The sealed data
 * @param[in]  sealed_size        The size of the sealed data
 * @param      plaintext          A pointer to buffer to store the plaintext
 * @param[in]  plaintext_max_len  The size of buffer prepared to store the
 *                                plaintext
 *
 * @return     Truthy if unseal successful, falsy otherwise.
 */
sgx_status_t unseal(sgx_sealed_data_t* sealed_data, uint32_t sealed_size, uint8_t* plaintext, uint32_t plaintext_len);


/**
 * @brief      Get the size of the unsealed data
 * 
 * @details    The size of the unsealed data is needed to allocate the buffer to store the unsealed data
 * 
 * @param      sealed_data        The sealed data
 * @param[in]  sealed_data_size   The size of the sealed data
 * 
 * @return     The size of the unsealed data
*/
uint32_t get_unsealed_data_size(uint8_t *sealed_data, uint32_t sealed_data_size);

/**
 * @brief      Get the size of the sealed data
 * 
 * @details    The size of the sealed data is needed to allocate the buffer to store the sealed data
 * 
 * @param[in]  plaintext_len    The size of the plaintext
 * 
 * @return     The size of the sealed data
*/
uint32_t get_sealed_data_size(uint32_t plaintext_len);

#if defined(__cplusplus)
}
#endif

#endif /* !_ENCLAVE1_H_ */
