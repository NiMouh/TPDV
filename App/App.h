#ifndef _APP_H_
#define _APP_H_

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>

#include "sgx_error.h" /* sgx_status_t */
#include "sgx_eid.h"   /* sgx_enclave_id_t */
#include "sgx_dh.h"

#define ENCLAVE1_FILENAME "enclave1.signed.so"
#define ENCLAVE2_FILENAME "enclave2.signed.so"

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

/* PATHS */
#define ASSETS_PATH "./assets/"
#define TPDVS_PATH "./tpdvs/"

#if defined(__cplusplus)
extern "C"
{
#endif

    /**
     * @file App.h
     *
     * @brief This file contains the definitions of the functions used in the Application
     *
     * @author Simão Andrade (118345)
     *         João Almeida (118340)
     */

    /**
     * @brief Structure to hold the Enclave error messages
     *
     * @details This structure is used to hold the error messages for the Enclave
     *
     */
    typedef struct _sgx_errlist_t
    {
        sgx_status_t error_number;
        const char *message;
    } sgx_errlist_t;

    /**
     * @brief Error codes for the Enclave
     *
     * @details The error codes are extracted from the sgx_error.h file
     */
    static sgx_errlist_t sgx_errlist[] =
        {
            {SGX_SUCCESS, "All is well!"},
            {SGX_ERROR_UNEXPECTED, "Unexpected error"},
            {SGX_ERROR_INVALID_PARAMETER, "The parameter is incorrect"},
            {SGX_ERROR_OUT_OF_MEMORY, "Not enough memory is available to complete this operation"},
            {SGX_ERROR_ENCLAVE_LOST, "Enclave lost after power transition or used in child process created by linux:fork()"},
            {SGX_ERROR_INVALID_STATE, "SGX API is invoked in incorrect order or state"},
            {SGX_ERROR_FEATURE_NOT_SUPPORTED, "Feature is not supported on this platform"},
            {SGX_PTHREAD_EXIT, "Enclave is exited with pthread_exit()"},
            {SGX_ERROR_MEMORY_MAP_FAILURE, "Failed to reserve memory for the enclave"},
            {SGX_ERROR_INVALID_FUNCTION, "The ecall/ocall index is invalid"},
            {SGX_ERROR_OUT_OF_TCS, "The enclave is out of TCS"},
            {SGX_ERROR_ENCLAVE_CRASHED, "The enclave is crashed"},
            {SGX_ERROR_ECALL_NOT_ALLOWED, "The ECALL is not allowed at this time, e.g. ecall is blocked by the dynamic entry table, or nested ecall is not allowed during initialization"},
            {SGX_ERROR_OCALL_NOT_ALLOWED, "The OCALL is not allowed at this time, e.g. ocall is not allowed during exception handling"},
            {SGX_ERROR_STACK_OVERRUN, "The enclave is running out of stack"},
            {SGX_ERROR_UNDEFINED_SYMBOL, "The enclave image has undefined symbol"},
            {SGX_ERROR_INVALID_ENCLAVE, "The enclave image is not correct"},
            {SGX_ERROR_INVALID_ENCLAVE_ID, "The enclave id is invalid"},
            {SGX_ERROR_INVALID_SIGNATURE, "The signature is invalid"},
            {SGX_ERROR_NDEBUG_ENCLAVE, "The enclave is signed as product enclave, and can not be created as debuggable enclave"},
            {SGX_ERROR_OUT_OF_EPC, "Not enough EPC is available to load the enclave"},
            {SGX_ERROR_NO_DEVICE, "Can't open SGX device"},
            {SGX_ERROR_MEMORY_MAP_CONFLICT, "Page mapping failed in driver"},
            {SGX_ERROR_INVALID_METADATA, "The metadata is incorrect"},
            {SGX_ERROR_DEVICE_BUSY, "Device is busy, mostly EINIT failed"},
            {SGX_ERROR_INVALID_VERSION, "Metadata version is inconsistent between uRTS and sgx_sign or uRTS is incompatible with current platform"},
            {SGX_ERROR_MODE_INCOMPATIBLE, "The target enclave 32/64 bit mode or sim/hw mode is incompatible with the mode of current uRTS"},
            {SGX_ERROR_ENCLAVE_FILE_ACCESS, "Can't open enclave file"},
            {SGX_ERROR_INVALID_MISC, "The MiscSelct/MiscMask settings are not correct"},
            {SGX_ERROR_INVALID_LAUNCH_TOKEN, "The launch token is not correct"},
            {SGX_ERROR_MAC_MISMATCH, "Indicates verification error for reports, sealed datas, etc"},
            {SGX_ERROR_INVALID_ATTRIBUTE, "The enclave is not authorized, e.g., requesting invalid attribute or launch key access on legacy SGX platform without FLC"},
            {SGX_ERROR_INVALID_CPUSVN, "The cpu svn is beyond platform's cpu svn value"},
            {SGX_ERROR_INVALID_ISVSVN, "The isv svn is greater than the enclave's isv svn"},
            {SGX_ERROR_INVALID_KEYNAME, "The key name is an unsupported value"},
            {SGX_ERROR_SERVICE_UNAVAILABLE, "Indicates aesm didn't respond or the requested service is not supported"},
            {SGX_ERROR_SERVICE_TIMEOUT, "The request to aesm timed out"},
            {SGX_ERROR_AE_INVALID_EPIDBLOB, "Indicates epid blob verification error"},
            {SGX_ERROR_SERVICE_INVALID_PRIVILEGE, " Enclave not authorized to run, .e.g. provisioning enclave hosted in an app without access rights to /dev/sgx_provision"},
            {SGX_ERROR_EPID_MEMBER_REVOKED, "The EPID group membership is revoked"},
            {SGX_ERROR_UPDATE_NEEDED, "SGX needs to be updated"},
            {SGX_ERROR_NETWORK_FAILURE, "Network connecting or proxy setting issue is encountered"},
            {SGX_ERROR_AE_SESSION_INVALID, "Session is invalid or ended by server"},
            {SGX_ERROR_BUSY, "The requested service is temporarily not available"},
            {SGX_ERROR_MC_NOT_FOUND, "The Monotonic Counter doesn't exist or has been invalided"},
            {SGX_ERROR_MC_NO_ACCESS_RIGHT, "Caller doesn't have the access right to specified VMC"},
            {SGX_ERROR_MC_USED_UP, "Monotonic counters are used out"},
            {SGX_ERROR_MC_OVER_QUOTA, "Monotonic counters exceeds quota limitation"},
            {SGX_ERROR_KDF_MISMATCH, "Key derivation function doesn't match during key exchange"},
            {SGX_ERROR_UNRECOGNIZED_PLATFORM, "EPID Provisioning failed due to platform not recognized by backend server"},
            {SGX_ERROR_UNSUPPORTED_CONFIG, "The config for trigging EPID Provisiong or PSE Provisiong&LTP is invalid"},
            {SGX_ERROR_NO_PRIVILEGE, "Not enough privilege to perform the operation"},
            {SGX_ERROR_PCL_ENCRYPTED, "trying to encrypt an already encrypted enclave"},
            {SGX_ERROR_PCL_NOT_ENCRYPTED, "trying to load a plain enclave using sgx_create_encrypted_enclave"},
            {SGX_ERROR_PCL_MAC_MISMATCH, "section mac result does not match build time mac"},
            {SGX_ERROR_PCL_SHA_MISMATCH, "Unsealed key MAC does not match MAC of key hardcoded in enclave binary"},
            {SGX_ERROR_PCL_GUID_MISMATCH, "GUID in sealed blob does not match GUID hardcoded in enclave binary"},
            {SGX_ERROR_FILE_BAD_STATUS, "The file is in bad status, run sgx_clearerr to try and fix it"},
            {SGX_ERROR_FILE_NO_KEY_ID, "The Key ID field is all zeros, can't re-generate the encryption key"},
            {SGX_ERROR_FILE_NAME_MISMATCH, "The current file name is different then the original file name (not allowed, substitution attack)"},
            {SGX_ERROR_FILE_NOT_SGX_FILE, "The file is not an SGX file"},
            {SGX_ERROR_FILE_CANT_OPEN_RECOVERY_FILE, "A recovery file can't be opened, so flush operation can't continue (only used when no EXXX is returned)"},
            {SGX_ERROR_FILE_CANT_WRITE_RECOVERY_FILE, "A recovery file can't be written, so flush operation can't continue (only used when no EXXX is returned)"},
            {SGX_ERROR_FILE_RECOVERY_NEEDED, "When openeing the file, recovery is needed, but the recovery process failed"},
            {SGX_ERROR_FILE_FLUSH_FAILED, "fflush operation (to disk) failed (only used when no EXXX is returned)"},
            {SGX_ERROR_FILE_CLOSE_FAILED, "fclose operation (to disk) failed (only used when no EXXX is returned)"},
            {SGX_ERROR_UNSUPPORTED_ATT_KEY_ID, "platform quoting infrastructure does not support the key"},
            {SGX_ERROR_ATT_KEY_CERTIFICATION_FAILURE, "Failed to generate and certify the attestation key"},
            {SGX_ERROR_ATT_KEY_UNINITIALIZED, "The platform quoting infrastructure does not have the attestation key available to generate quote"},
            {SGX_ERROR_INVALID_ATT_KEY_CERT_DATA, "TThe data returned by the platform library's sgx_get_quote_config() is invalid"},
            {SGX_ERROR_PLATFORM_CERT_UNAVAILABLE, "The PCK Cert for the platform is not available"},
            {SGX_INTERNAL_ERROR_ENCLAVE_CREATE_INTERRUPTED, "The ioctl for enclave_create unexpectedly failed with EINTR"}};

    /**
     * @brief Variables to hold the Enclave 1 ID
     *
     * @details These variable is used to hold the Enclave ID for the Enclave 1
     */
    sgx_enclave_id_t global_eid1 = 0;

    /**
     * @brief Variables to hold the Enclave 2 ID
     *
     * @details These variable is used to hold the Enclave ID for the Enclave 2
     */
    sgx_enclave_id_t global_eid2 = 0;

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
     * @brief Hash the data using SHA256 from the OpenSSL library
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
    int create_tpdv(const uint8_t *filename, const uint32_t filename_size, const uint8_t *password, const uint32_t password_size, const uint8_t *creator, const uint32_t creator_size);

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
