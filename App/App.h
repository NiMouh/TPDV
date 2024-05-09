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

/**
 * @brief Read the file into a buffer
 * 
 * @param filename The name of the file to read
 * @param buf The buffer to read the file into
 * @param bsize The size of the buffer
 * 
 * @return True if the read was successful, False otherwise
*/
static bool read_file_to_buf(const char *filename, uint8_t *buf, uint32_t bsize);

/**
 * @brief Write the buffer to a file
 * 
 * @param filename The name of the file to write
 * @param buf The buffer to write to the file
 * @param bsize The size of the buffer
 * 
 * @return True if the write was successful, False otherwise
*/
static bool write_buf_to_file(const uint8_t *filename, const uint8_t *buf, uint32_t bsize, long offset);

/**
 * @brief Hash the data using SHA256
 * 
 * @param data The data to hash
 * @param data_len The length of the data
 * 
 * @return The hash of the data
*/
uint8_t *sha256_hash(const uint8_t *data, uint32_t data_len);

/**
 * @brief Create a TPDV
 * 
 * @details Create a TPDV by creating the file header with the name of the vault, password, creator, number of assets and nonce (both starting at 0) and save it to file sealed with the Enclave's key.
 * 
 * @param filename The name of the TPDV
 * @param filename_size The size of the filename
 * @param password The password of the TPDV
 * @param password_size The size of the password
 * @param creator The creator of the TPDV
 * @param creator_size The size of the creator
 * 
 * @return 0 if the TPDV was created successfully, 1 otherwise
*/
int create_tpdv(const uint8_t *filename,const uint32_t filename_size,const uint8_t *password,const uint32_t password_size,const uint8_t *creator,const uint32_t creator_size);

/**
 * @brief List all the assets in a TPDV sealed with the Enclave 2 key
 * 
 * @details It will unsealed the content inside the enclave, obtain the asset files and print them to the console (using an OCALL).
 * 
 * @param filename The name of the TPDV
 * @param password The password of the TPDV
 * 
 * @return 0 if the assets were listed successfully, 1 otherwise
*/
int list_all_assets2(const uint8_t *filename, const uint8_t *password);

/**
 * @brief Retrieve an asset from a TPDV sealed with the Enclave 1 key
 * 
 * @details It will unsealed the content inside the enclave, obtain the asset files and print them to the console (using an OCALL).
 * 
 * @param filename The name of the TPDV
 * @param password The password of the TPDV
 * @param asset_filename The name of the asset to retrieve
 * 
 * @return 0 if the asset was retrieved successfully, 1 otherwise
*/
int list_all_assets(const uint8_t *sealed_data, uint32_t sealed_size);

/**
 * @brief Retrieve an asset file from a TPDV sealed with the Enclave key
 * 
 * @details It will unsealed the content inside the enclave, obtain the asset file, send it outside the enclave and then save it to a file.
 * 
 * @param filename The name of the TPDV
 * @param password The password of the TPDV
 * @param asset_filename The name of the asset to retrieve
 * 
 * @return 0 if the asset was retrieved successfully, 1 otherwise
*/
int retrieve_asset(const uint8_t *filename, const uint8_t *password, const uint8_t *asset_filename);

/**
 * @brief Change the password of a TPDV sealed with the Enclave key
 * 
 * @details It will unsealed the content inside the enclave, change the password and save it back to the file sealed with the Enclave's key.
 * 
 * @param filename The name of the TPDV
 * @param old_password The old password of the TPDV
 * @param new_password The new password of the TPDV
 * 
 * @return 0 if the password was changed successfully, 1 otherwise
*/
int change_password(const uint8_t *filename, const uint8_t *old_password, const uint8_t *new_password);

/**
 * @brief Check the integrity of an asset sealed with the Enclave key
 * 
 * @details It will unsealed the content inside the enclave, and compare the hash of the asset with the hash of the file.
 * 
 * @param filename The name of the TPDV
 * @param password The password of the TPDV
 * @param asset_filename The name of the asset to check
 * 
 * @return 0 if the asset is intact, 1 otherwise
*/
int check_asset_integrity(const uint8_t *filename, const uint8_t *password, const uint8_t *asset_filename);

/**
 * @brief Clone a TPDV sealed with the Enclave key
 * 
 * @details Using diffie-hellman key exchange, it will exchange keys with the Enclave 2, unseal and cipher the content inside the Enclave 1, send to the Application for then to be deciphered and sealed with the Enclave 2 key.
 * 
 * @param original_tpdv The name of the TPDV to clone
 * @param original_password The password of the TPDV to clone
 * @param cloned_tpdv The name of the cloned TPDV
 * @param cloned_password The password of the cloned TPDV
 * 
 * @return 0 if the TPDV was cloned successfully, 1 otherwise
*/
int clone_tpdv(const uint8_t *original_tpdv, const uint8_t *original_password, const uint8_t *cloned_tpdv, const uint8_t *cloned_password);

/**
 * @brief Add an asset to a TPDV sealed with the Enclave key
 * 
 * @details It will unsealed the content inside the enclave, add the asset file and change the nonce and total number of assets, then save it back to the file sealed with the Enclave's key.
 * 
 * @param filename The name of the TPDV
 * @param password The password of the TPDV
 * @param asset_filename The name of the asset to add
 * 
 * @return 0 if the asset was added successfully, 1 otherwise
*/
int add_asset(const uint8_t *filename, const uint8_t *password, const uint8_t *asset_filename);


#if defined(__cplusplus)
}
#endif

#endif /* !_APP_H_ */
