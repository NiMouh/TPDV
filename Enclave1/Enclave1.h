#ifndef _ENCLAVE1_H_
#define _ENCLAVE1_H_

#include <stdlib.h>
#include <assert.h>
#include "sgx_dh.h"

#if defined(__cplusplus)
extern "C"
{
#endif

/**
 * @file Enclave1.h
 *
 * @brief Enclave 1 functions and variables
 *
 * This file contains the functions and variables used by Enclave 1.
 *
 * @author João Almeida  (118340)
 *         Simão Andrade (118345)
 * @see Enclave1.cpp
 */

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

    /**
     * @brief Print a string to the application console
     *
     * @details This function prints a string to the enclave console using the ocall_e1_print_string function.
     *
     * @param str The string to be printed
     *
     * @return The result of the printing operation
     */
    int printf(const char *fmt, ...);

    /**
     * @brief Seal the plaintext data
     *
     * @details This function seals the plaintext data using the SGX seal function and saves the sealed data in the sealed_data parameter.
     *
     * @param plaintext The plaintext data to be sealed
     * @param plaintext_len The length of the plaintext data
     * @param sealed_data The sealed data
     * @param sealed_size The size of the sealed data
     *
     * @return The result of the sealing operation
     */
    sgx_status_t seal(uint8_t *plaintext, uint32_t plaintext_len, sgx_sealed_data_t *sealed_data, uint32_t sealed_size);

    /**
     * @brief Unseal the sealed data
     *
     * @details This function unseals the sealed data using the SGX unseal function and saves the plaintext data in the plaintext parameter.
     *
     * @param sealed_data The sealed data to be unsealed
     * @param sealed_size The size of the sealed data
     * @param plaintext The plaintext data
     * @param plaintext_len The length of the plaintext data
     *
     * @return The result of the unsealing operation
     */
    sgx_status_t unseal(sgx_sealed_data_t *sealed_data, uint32_t sealed_size, uint8_t *plaintext, uint32_t plaintext_len);

    /**
     * @brief Get the size of the plaintext data from the sealed data
     *
     * @details This function returns the size of the plaintext data from the sealed data.
     *
     * @param sealed_data The sealed data
     * @param sealed_data_size The size of the sealed data
     *
     * @return The size of the plaintext data
     */
    uint32_t get_unsealed_data_size(uint8_t *sealed_data, uint32_t sealed_data_size);

    /**
     * @brief Get the size of the sealed data
     *
     * @details This function returns the size of the sealed data.
     *
     * @param plaintext_len The length of the plaintext data
     *
     * @return The size of the sealed data
     */
    uint32_t get_sealed_data_size(uint32_t plaintext_len);

    /**
     * @brief Initialize the session
     *
     * @details This variable represents one side of the session between the two enclaves.
     */
    static sgx_dh_session_t e1_session;

    /**
     * @brief Agreement Encryption Key
     *
     * @details This variable represents the key used to encrypt the data between the two enclaves.
     */
    static sgx_key_128bit_t e1_aek;

    /**
     * @brief Responder Identity
     *
     * @details This variable represents the identity of the responder enclave.
     */
    static sgx_dh_session_enclave_identity_t e1_responder_identity;

    /**
     * @brief Initialize the session
     *
     * @details This function represents the 1st step of the key exchange protocol. Initializes the session from the enclave 1 side.
     *
     * @param dh_status pointer to the status of the operation
     */
    void e1_init_session(sgx_status_t *dh_status);

    /**
     * @brief Process the message 2
     *
     * @details This function represents the 5th step of the key exchange protocol. Receives the 1st message from the responder enclave, processes and then send the 2nd message.
     *
     * @param msg2 The message 2
     * @param dh_status pointer to the status of the operation
     */
    void e1_generate_message1(sgx_dh_msg1_t *msg1, sgx_status_t *dh_status);

    /**
     * @brief Process the message 3
     *
     * @details This function represents the 9th step of the key exchange protocol. Receives the 3rd message from the responder enclave and processes it.
     *
     * @param msg3 The message 3
     * @param dh_status pointer to the status of the operation
     */
    void e1_process_message2(const sgx_dh_msg2_t *msg2, sgx_dh_msg3_t *msg3, sgx_status_t *dh_status);

    /**
     * @brief Show the secret key
     *
     * @details This function prints the secret key of the enclave 1 to the console.
     */
    void e1_show_secret_key(void);

    /**
     * @brief Check the password validity
     *
     * @details This function checks if the provided password is correct by comparing it with the password stored in the sealed data.
     *
     * @param password The password to be checked
     * @param password_size The size of the password
     * @param sealed_data The sealed data containing the password
     * @param sealed_size The size of the sealed data
     * @param result pointer to the result of the operation
     *
     * @return The result of the operation
     */
    void e1_check_password(const uint8_t *password, uint32_t password_size, const uint8_t *sealed_data, uint32_t sealed_size, int *result);

    /**
     * @brief Check the nonce validity
     *
     * @details This function checks if the nonce is correct by hashing the assets and comparing the result with the stored nonce.
     *
     * @param sealed_data The sealed data containing the assets
     * @param sealed_size The size of the sealed data
     * @param result pointer to the result of the operation
     *
     * @return The result of the operation
     */
    void e1_check_nonce(const uint8_t *sealed_data, uint32_t sealed_size, int *result);

    /**
     * @brief Add an asset to the vault
     *
     * @details This function adds an asset to the vault by unsealing the data, appending the asset to the end of the vault, hashing the assets, and sealing the data again.
     *
     * @param asset_filename The filename of the asset
     * @param asset_filename_size The size of the asset filename
     * @param sealed_data The sealed data containing the assets
     * @param sealed_size The size of the sealed data
     * @param asset The asset to be added
     * @param asset_size The size of the asset
     * @param new_sealed_data The sealed data with the new asset
     * @param new_sealed_size The size of the new sealed data
     */
    void e1_add_asset(const uint8_t *asset_filename, uint32_t asset_filename_size, const uint8_t *sealed_data, uint32_t sealed_size, const uint8_t *asset, uint32_t asset_size, uint8_t *new_sealed_data, uint32_t new_sealed_size);

    /**
     * @brief List all the assets in the vault
     *
     * @details This function lists all the assets in the vault by unsealing the data, iterating through the assets and printing them through the custom print function.
     *
     * @param sealed_data The sealed data containing the assets
     * @param sealed_size The size of the sealed data
     */
    void e1_list_all_assets(const uint8_t *sealed_data, uint32_t sealed_size);

    /**
     * @brief Get the size of an asset in the vault
     *
     * @details This function gets the size of an asset in the vault by unsealing the data, iterating through the assets, and returning the size of the asset.
     *
     * @param asset_filename The filename of the asset
     * @param asset_filename_size The size of the asset filename
     * @param sealed_data The sealed data containing the assets
     * @param sealed_size The size of the sealed data
     * @param asset_size pointer to the size of the asset
     */
    void e1_get_asset_size(const uint8_t *asset_filename, uint32_t asset_filename_size, const uint8_t *sealed_data, uint32_t sealed_size, uint32_t *asset_size);

    /**
     * @brief Retrieve an asset from the vault
     *
     * @details This function retrieves an asset from the vault by unsealing the data, iterating through the assets, and copying the asset content to the provided buffer.
     *
     * @param asset_filename The filename of the asset
     * @param asset_filename_size The size of the asset filename
     * @param sealed_data The sealed data containing the assets
     * @param sealed_size The size of the sealed data
     * @param asset The buffer to store the asset content
     * @param asset_size The size of the asset buffer
     */
    void e1_retrieve_asset(const uint8_t *asset_filename, uint32_t asset_filename_size, const uint8_t *sealed_data, uint32_t sealed_size, uint8_t *asset, uint32_t asset_size);

    /**
     * @brief Change the password of the vault
     *
     * @details This function changes the password of the vault by unsealing the data, changing the password, and sealing the data again.
     *
     * @param old_password The old password
     * @param old_password_size The size of the old password
     * @param new_password The new password
     * @param new_password_size The size of the new password
     * @param sealed_data The sealed data containing the assets
     * @param sealed_size The size of the sealed data
     * @param new_sealed_data The sealed data with the new password
     * @param new_sealed_size The size of the new sealed data
     */
    void e1_change_password(const uint8_t *old_password, uint32_t old_password_size, const uint8_t *new_password, uint32_t new_password_size, const uint8_t *sealed_data, uint32_t sealed_size, uint8_t *new_sealed_data, uint32_t new_sealed_size);

    /**
     * @brief Obtain the hash of one asset in the vault
     * 
     * @details This function obtains the hash of one asset in the vault by unsealing the data, iterating through the assets, and hashing the asset content.
     * 
     * @param asset_filename The filename of the asset
     * @param asset_filename_size The size of the asset filename
     * @param sealed_data The sealed data containing the assets
     * @param sealed_size The size of the sealed data
     * @param hash A pointer to the buffer to store the asset hash
     * @param hash_size The size of the hash buffer
     */
    void e1_get_asset_hash_from_vault(const uint8_t *asset_filename, uint32_t asset_filename_size, const uint8_t *sealed_data, uint32_t sealed_size, uint8_t *hash, uint32_t hash_size);

    /**
     * @brief Cipher the sealed data using the AEK
     *
     * @details This function ciphers the sealed data using the AEK and saves the ciphertext in the ciphertext parameter.
     *
     * @param sealed_data The sealed data to be ciphered
     * @param sealed_size The size of the sealed data
     * @param ciphertext The ciphertext
     * @param ciphertext_size The size of the ciphertext
     */
    void e1_unseal_and_cipher(const uint8_t *sealed_data, uint32_t sealed_size, uint8_t *ciphertext, uint32_t ciphertext_size);

#if defined(__cplusplus)
}
#endif

#endif /* !_ENCLAVE1_H_ */
