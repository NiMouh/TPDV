#ifndef _ENCLAVE2_H_
#define _ENCLAVE2_H_

#include <stdlib.h>
#include <assert.h>
#include "sgx_dh.h"

/* Hashes */
#define SHA256_DIGEST_LENGTH 32

/* TPDV SIZES */
#define FILENAME_SIZE 20                                                                      // bytes
#define CREATOR_SIZE 20                                                                       // bytes
#define PASSWORD_SIZE 20                                                                      // bytes
#define NONCE_SIZE 4                                                                          // bytes
#define ASSETS_SIZE 4                                                                         // bytes
#define HEADER_SIZE (FILENAME_SIZE + CREATOR_SIZE + PASSWORD_SIZE + ASSETS_SIZE + NONCE_SIZE) // bytes
#define MAX_ASSETS 16000                                                                      // 16MB / 1KB = 16K assets

/* ASSET SIZES */
#define ASSETNAME_SIZE 20 // bytes

#if defined(__cplusplus)
extern "C"
{
#endif

    /**
     * @file Enclave2.h
     *
     * @brief This file contains the declarations of the functions that are used in Enclave2.cpp
     *
     * @author João Almeida  (118340)
     *         Simão Andrade (118345)
     *
     * @see Enclave2.cpp
     */

    /**
     * @brief Prints a formatted string to the standard output using a OCALL to the untrusted side
     *
     * @param fmt The format string
     * @param ... The arguments to be printed
     *
     * @return The number of characters printed
     */
    int printf(const char *fmt, ...);

    /**
     * @brief Lists all the assets in the vault
     *
     * @param sealed_data The sealed data
     * @param sealed_size The size of the sealed data
     */
    void e2_list_all_assets(const uint8_t *sealed_data, uint32_t sealed_size);

    /**
     * @brief Adds an asset to the vault
     *
     * @param sealed_data The sealed data
     * @param sealed_size The size of the sealed data
     * @param asset_name The name of the asset
     * @param asset_content The content of the asset
     * @param asset_size The size of the asset
     */
    void e2_check_password(const uint8_t *password, uint32_t password_size, const uint8_t *sealed_data, uint32_t sealed_size, int *result);

    /**
     * @brief Initializes the session for the Diffie-Hellman key exchange
     *
     * @param dh_status The status of the Diffie-Hellman key exchange
     */
    void e2_init_session(sgx_status_t *dh_status);

    /**
     * @brief Generates the first message of the Diffie-Hellman key exchange
     *
     * @param msg1 The first message
     * @param dh_status The status of the Diffie-Hellman key exchange
     */
    void e2_generate_message1(sgx_dh_msg1_t *msg1, sgx_status_t *dh_status);

    /**
     * @brief Processes the second message of the Diffie-Hellman key exchange
     *
     * @param msg2 The second message
     * @param msg3 The third message
     * @param dh_status The status of the Diffie-Hellman key exchange
     */
    void e2_process_message2(const sgx_dh_msg2_t *msg2, sgx_dh_msg3_t *msg3, sgx_status_t *dh_status);

    /**
     * @brief Shows the secret key
     */
    void e2_show_secret_key(void);

    /**
     * @brief Deciphers and seals the data
     *
     * @param ciphertext The ciphertext
     * @param ciphertext_size The size of the ciphertext
     * @param password The password
     * @param password_size The size of the password
     * @param sealed_data The sealed data
     * @param sealed_size The size of the sealed data
     */
    void e2_decipher_and_seal(const uint8_t *ciphertext, uint32_t ciphertext_size, const uint8_t *password, uint32_t password_size, uint8_t *sealed_data, uint32_t sealed_size);

#if defined(__cplusplus)
}
#endif

#endif /* !_ENCLAVE2_H_ */
