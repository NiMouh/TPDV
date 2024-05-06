#include <time.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <iostream>
#include <fstream>
#include <openssl/sha.h>
#include <openssl/evp.h>

#include "sgx_urts.h"
#include "App.h"
#include "Enclave1_u.h"

uint8_t *sha256_hash(const uint8_t *data, uint32_t data_len)
{
  // Allocate memory for the hash result
  uint8_t *hash_result = (uint8_t *)malloc(SHA256_DIGEST_LENGTH);
  if (!hash_result)
  {
    // Memory allocation failed
    return NULL;
  }

  EVP_MD_CTX *mdctx;
  const EVP_MD *md;
  unsigned int md_len;

  // Create new EVP_MD_CTX object
  mdctx = EVP_MD_CTX_new();
  if (mdctx == NULL)
  {
    // EVP_MD_CTX creation failed
    free(hash_result);
    return NULL;
  }

  // Initialize the EVP_MD_CTX with the SHA-256 digest type
  md = EVP_sha256();

  // Initialize the digest operation
  if (1 != EVP_DigestInit_ex(mdctx, md, NULL))
  {
    // Error initializing digest operation
    EVP_MD_CTX_free(mdctx);
    free(hash_result);
    return NULL;
  }

  // Update hash with the data
  if (1 != EVP_DigestUpdate(mdctx, data, data_len))
  {
    // Error updating hash
    EVP_MD_CTX_free(mdctx);
    free(hash_result);
    return NULL;
  }

  // Finalize hash
  if (1 != EVP_DigestFinal_ex(mdctx, hash_result, &md_len))
  {
    // Error finalizing hash
    EVP_MD_CTX_free(mdctx);
    free(hash_result);
    return NULL;
  }

  // Clean up EVP_MD_CTX
  EVP_MD_CTX_free(mdctx);

  // Return the hash result
  return hash_result;
}

/*
 * Error reporting
 */

typedef struct _sgx_errlist_t
{
  sgx_status_t error_number;
  const char *message;
} sgx_errlist_t;

static sgx_errlist_t sgx_errlist[] =
    {/* error list extracted from /opt/intel/sgxsdk/include/sgx_error.h */
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

void print_error_message(sgx_status_t ret, const char *sgx_function_name)
{
  uint32_t ttl = sizeof(sgx_errlist) / sizeof(sgx_errlist[0]);
  uint32_t idx;

  if (sgx_function_name != NULL)
    printf("Function: %s\n", sgx_function_name);
  for (idx = 0; idx < ttl; idx++)
  {
    if (ret == sgx_errlist[idx].error_number)
    {
      printf("Error: %s\n", sgx_errlist[idx].message);
      break;
    }
  }
  if (idx == ttl)
    printf("Error code is 0x%X. Please refer to the \"Intel SGX SDK Developer Reference\" for more details.\n", ret);
}

/*
 * Enclave stuff
 */

sgx_enclave_id_t global_eid1 = 0;

int initialize_enclave1(void)
{
  sgx_status_t ret;

  if ((ret = sgx_create_enclave(ENCLAVE1_FILENAME, SGX_DEBUG_FLAG, NULL, NULL, &global_eid1, NULL)) != SGX_SUCCESS)
  {
    print_error_message(ret, "sgx_create_enclave");
    return -1;
  }
  return 0;
}

void ocall_e1_print_string(const char *str)
{
  printf("%s", str);
}

/* FILE MANAGEMENT FUNCTIONS */

static uint32_t get_file_size(const uint8_t *filename)
{

  char path[FILENAME_SIZE + 9] = "./vaults/";

  for (int i = 0; i < FILENAME_SIZE; i++)
  {
    if (filename[i] == '\0')
      break;
    path[i + 9] = filename[i];
  }

  std::ifstream ifs(path, std::ios::binary);
  if (!ifs.good())
  {
    std::cout << "Failed to open the file \"" << path << "\"" << std::endl;
    return -1;
  }
  ifs.seekg(0, std::ios::end);
  uint32_t size = ifs.tellg();
  ifs.close();
  return size;
}

static bool read_file_to_buf(const char *filename, uint8_t *buf, uint32_t bsize)
{
  if (filename == NULL || buf == NULL || bsize == 0)
    return false;

  char path[FILENAME_SIZE + 9] = "./vaults/";

  for (int i = 0; i < FILENAME_SIZE; i++)
  {
    if (filename[i] == '\0')
      break;
    path[i + 9] = filename[i];
  }

  std::ifstream ifs(path, std::ios::binary);
  if (!ifs.good())
  {
    std::cout << "Failed to open the file \"" << path << "\"" << std::endl;
    return false;
  }
  ifs.read(reinterpret_cast<char *>(buf), bsize);
  if (ifs.fail())
  {
    std::cout << "Failed to read the file \"" << path << "\"" << std::endl;
    return false;
  }
  return true;
}

static bool write_buf_to_file(const uint8_t *filename, const uint8_t *buf, uint32_t bsize, long offset)
{
  if (filename == NULL || buf == NULL || bsize == 0)
    return false;

  char path[FILENAME_SIZE + 9] = "./vaults/";

  for (int i = 0; i < FILENAME_SIZE; i++)
  {
    if (filename[i] == '\0')
      break;
    path[i + 9] = filename[i];
  }

  // Save file in the vaults directory
  FILE *file = fopen(path, "wb");
  if (!file)
  {
    fprintf(stderr, "Failed to open the file \"%s\"\n", path);
    return false;
  }

  fseek(file, offset, SEEK_SET);
  fwrite(buf, 1, bsize, file);
  fclose(file);

  return true;
}

/* APPLICATION FUNCTIONS */

int create_tpdv(const uint8_t *filename, const uint32_t filename_size, const uint8_t *password, const uint32_t password_size, const uint8_t *creator, const uint32_t creator_size)
{

  if (initialize_enclave1() < 0)
  {
    fprintf(stderr, "Error initializing enclave\n");
    return -1;
  }

  uint32_t total_header_size = filename_size + password_size + creator_size + 4 + 4; // for the number of assets and for the none (last 4 bytes of the hash of all the assets)
  uint8_t header[total_header_size] = {0};
  memcpy(header, filename, filename_size);
  memcpy(header + filename_size, password, password_size);
  memcpy(header + filename_size + password_size, creator, creator_size);

  // Calculate sealed data size
  uint32_t sealed_size = 0;
  sgx_status_t status;
  if ((status = get_sealed_data_size(global_eid1, &sealed_size, total_header_size)) != SGX_SUCCESS)
  {
    print_error_message(status, "get_sealed_data_size");
    return 1;
  }

  uint8_t *sealed_data = (uint8_t *)malloc(sealed_size);
  if (sealed_data == NULL)
  {
    fprintf(stderr, "Failed to allocate memory for the sealed data\n");
    return 1;
  }

  sgx_status_t ecall_status;
  if ((status = seal(global_eid1, &ecall_status, header, total_header_size, (sgx_sealed_data_t *)sealed_data, sealed_size)) != SGX_SUCCESS)
  {
    print_error_message(status, "seal");
    free(sealed_data);
    return 1;
  }

  if (!write_buf_to_file(filename, sealed_data, sealed_size, 0))
  {
    fprintf(stderr, "Failed to write the sealed data to the file\n");
    free(sealed_data);
    return 1;
  }

  free(sealed_data);

  if ((status = sgx_destroy_enclave(global_eid1)) != SGX_SUCCESS)
  {
    print_error_message(status, "sgx_destroy_enclave");
    return 1;
  }

  return 0;
}

int add_asset(const uint8_t *filename, const uint8_t *password, const uint8_t *asset_filename)
{
  // Read the asset file
  uint32_t asset_size = get_file_size(asset_filename);
  if (asset_size == -1)
  {
    fprintf(stderr, "The asset file does not exist\n");
    return 1;
  }

  uint8_t *asset_data = (uint8_t *)malloc(asset_size);
  if (!read_file_to_buf((char *)asset_filename, asset_data, asset_size))
  {
    fprintf(stderr, "Failed to read the asset file\n");
    free(asset_data);
    return 1;
  }

  sgx_status_t status;
  if (initialize_enclave1() < 0)
  {
    fprintf(stderr, "Error initializing enclave\n");
    return -1;
  }

  uint32_t sealed_size = get_file_size(filename);
  if (sealed_size == -1)
  {
    fprintf(stderr, "The vault file does not exist\n");
    return 1;
  }

  uint8_t *sealed_data = (uint8_t *)malloc(sealed_size);
  if (sealed_data == NULL)
  {
    fprintf(stderr, "Failed to allocate memory for the sealed data\n");
    return 1;
  }

  if (!read_file_to_buf((char *)filename, sealed_data, sealed_size))
  {
    fprintf(stderr, "Failed to read the vault file\n");
    free(sealed_data);
    return 1;
  }

  int result = 0;
  if ((status = e1_check_password(global_eid1, password, PASSWORD_SIZE, sealed_data, sealed_size, &result)) != SGX_SUCCESS)
  {
    print_error_message(status, "check_password");
    free(sealed_data);
    return 1;
  }

  if (!result)
  {
    fprintf(stderr, "The password is incorrect\n");
    free(sealed_data);
    return 1;
  }

  // Get the new unsealed size
  uint32_t unsealed_size = 0;

  if ((status = get_unsealed_data_size(global_eid1, &unsealed_size, sealed_data, sealed_size)) != SGX_SUCCESS)
  {
    print_error_message(status, "get_unsealed_data_size");
    free(sealed_data);
    return 1;
  }
  uint32_t new_unsealed_size = unsealed_size + ASSETNAME_SIZE + 4 + asset_size;

  // Create the new_sealed_data size
  uint32_t new_sealed_size = 0;
  if ((status = get_sealed_data_size(global_eid1, &new_sealed_size, new_unsealed_size)) != SGX_SUCCESS)
  {
    print_error_message(status, "get_sealed_data_size");
    free(sealed_data);
    return 1;
  }
  uint8_t *new_sealed_data = (uint8_t *)malloc(new_sealed_size);
  if (new_sealed_data == NULL)
  {
    fprintf(stderr, "Failed to allocate memory for the new sealed data\n");
    free(sealed_data);
    return 1;
  }

  if ((status = e1_add_asset(global_eid1, asset_filename, ASSETNAME_SIZE, sealed_data, sealed_size, asset_data, asset_size, new_sealed_data, new_sealed_size)) != SGX_SUCCESS)
  {
    print_error_message(status, "add_asset");
    free(sealed_data);
    free(new_sealed_data);
    return 1;
  }

  if (!write_buf_to_file(filename, new_sealed_data, new_sealed_size, 0))
  {
    fprintf(stderr, "Failed to write the sealed new vault to the file\n");
    free(sealed_data);
    free(asset_data);
    return 1;
  }

  if ((status = sgx_destroy_enclave(global_eid1)) != SGX_SUCCESS)
  {
    print_error_message(status, "sgx_destroy_enclave");
    return 1;
  }

  return 0;
}

int list_all_assets(const uint8_t *filename, const uint8_t *password)
{
  sgx_status_t status, ecall_status;
  if (initialize_enclave1() < 0)
  {
    fprintf(stderr, "Error initializing enclave\n");
    return -1;
  }

  uint32_t sealed_size = get_file_size(filename);
  if (sealed_size == -1)
  {
    fprintf(stderr, "The vault file does not exist\n");
    return 1;
  }

  uint8_t *sealed_data = (uint8_t *)malloc(sealed_size);
  if (sealed_data == NULL)
  {
    fprintf(stderr, "Failed to allocate memory for the sealed data\n");
    return 1;
  }

  if (!read_file_to_buf((char *)filename, sealed_data, sealed_size))
  {
    fprintf(stderr, "Failed to read the vault file\n");
    free(sealed_data);
    return 1;
  }

  int result = 0;
  if ((status = e1_check_password(global_eid1, password, PASSWORD_SIZE, sealed_data, sealed_size, &result)) != SGX_SUCCESS)
  {
    print_error_message(status, "check_password");
    free(sealed_data);
    return 1;
  }

  if (!result)
  {
    fprintf(stderr, "The password is incorrect\n");
    free(sealed_data);
    return 1;
  }

  /* START */

  uint32_t unsealed_size = 0;
  if ((status = get_unsealed_data_size(global_eid1, &unsealed_size, sealed_data, sealed_size)) != SGX_SUCCESS)
  {
    print_error_message(status, "get_unsealed_data_size");
    free(sealed_data);
    return 1;
  }

  uint8_t *unsealed_data = (uint8_t *)malloc(unsealed_size);
  if (unsealed_data == NULL)
  {
    fprintf(stderr, "Failed to allocate memory for the unsealed data\n");
    free(sealed_data);
    return 1;
  }

  if ((status = unseal(global_eid1, &ecall_status, (sgx_sealed_data_t *)sealed_data, sealed_size, unsealed_data, unsealed_size)) != SGX_SUCCESS)
  {
    print_error_message(status, "unseal");
    free(sealed_data);
    free(unsealed_data);
    return 1;
  }

  uint32_t number_of_assets = 0;
  memcpy(&number_of_assets, unsealed_data + FILENAME_SIZE + PASSWORD_SIZE + CREATOR_SIZE, ASSETS_SIZE);

  if (number_of_assets == 0)
  {
    fprintf(stderr, "The vault is empty\n");
    free(sealed_data);
    free(unsealed_data);
    return 1;
  }

  int offset = HEADER_SIZE; // Skip the header
  for (int index = 0; index < (int)number_of_assets; index++)
  {
    uint8_t asset_name[ASSETNAME_SIZE + 1] = {0}; // +1 for null terminator
    memcpy(asset_name, unsealed_data + offset, ASSETNAME_SIZE);
    asset_name[ASSETNAME_SIZE] = '\0'; // Null terminate the string

    uint32_t asset_size = 0;
    memcpy(&asset_size, unsealed_data + offset + ASSETNAME_SIZE, sizeof(uint32_t));

    uint8_t asset_content[asset_size + 1]; // +1 for null terminator
    memcpy(asset_content, unsealed_data + offset + ASSETNAME_SIZE + sizeof(uint32_t), asset_size);
    asset_content[asset_size] = '\0'; // Null terminate the string

    offset += ASSETNAME_SIZE + sizeof(uint32_t) + asset_size;

    printf("ASSET %d\n\n", index + 1);
    printf("Filename: %s\n", (char *)asset_name);
    printf("Content size: %u\n", asset_size);
    printf("Content: %s\n", (char *)asset_content);
    printf("\n\n");
  }

  /* END */

  if ((status = sgx_destroy_enclave(global_eid1)) != SGX_SUCCESS)
  {
    print_error_message(status, "sgx_destroy_enclave");
    return 1;
  }

  return 0;
}

int retrieve_asset(const uint8_t *filename, const uint8_t *password, const uint8_t *asset_filename)
{
  sgx_status_t status, ecall_status;
  if (initialize_enclave1() < 0)
  {
    fprintf(stderr, "Error initializing enclave\n");
    return -1;
  }

  uint32_t sealed_size = get_file_size(filename);
  if (sealed_size == -1)
  {
    fprintf(stderr, "The vault file does not exist\n");
    return 1;
  }

  uint8_t *sealed_data = (uint8_t *)malloc(sealed_size);
  if (sealed_data == NULL)
  {
    fprintf(stderr, "Failed to allocate memory for the sealed data\n");
    return 1;
  }

  if (!read_file_to_buf((char *)filename, sealed_data, sealed_size))
  {
    fprintf(stderr, "Failed to read the vault file\n");
    free(sealed_data);
    return 1;
  }

  int result = 0;
  if ((status = e1_check_password(global_eid1, password, PASSWORD_SIZE, sealed_data, sealed_size, &result)) != SGX_SUCCESS)
  {
    print_error_message(status, "check_password");
    free(sealed_data);
    return 1;
  }

  if (!result)
  {
    fprintf(stderr, "The password is incorrect\n");
    free(sealed_data);
    return 1;
  }

  /* START */

  uint32_t unsealed_size = 0;
  if ((status = get_unsealed_data_size(global_eid1, &unsealed_size, sealed_data, sealed_size)) != SGX_SUCCESS)
  {
    print_error_message(status, "get_unsealed_data_size");
    free(sealed_data);
    return 1;
  }

  // Unseal the vault
  uint8_t *unsealed_data = (uint8_t *)malloc(unsealed_size);
  if (unsealed_data == NULL)
  {
    fprintf(stderr, "Failed to allocate memory for the unsealed data\n");
    free(sealed_data);
    return 1;
  }

  if ((status = unseal(global_eid1, &ecall_status, (sgx_sealed_data_t *)sealed_data, sealed_size, unsealed_data, unsealed_size)) != SGX_SUCCESS)
  {
    print_error_message(status, "unseal");
    free(sealed_data);
    free(unsealed_data);
    return 1;
  }

  uint8_t asset_name[ASSETNAME_SIZE] = {0};
  uint8_t *asset_content = NULL;
  uint32_t asset_size = 0;

  // Check how many assets are in the vault
  uint32_t number_of_assets = 0;
  memcpy(&number_of_assets, unsealed_data + HEADER_SIZE - NONCE_SIZE, ASSETS_SIZE);

  int offset = HEADER_SIZE; // Skip the header
  for (int index = 0; index < (int)number_of_assets; index++)
  {
    if(offset >= unsealed_size)
    {
      fprintf(stderr, "The asset does not exist\n");
      free(sealed_data);
      free(unsealed_data);
      return 1;
    }

    memcpy(asset_name, unsealed_data + offset, ASSETNAME_SIZE);
    
    offset += ASSETNAME_SIZE;
    memcpy(&asset_size, unsealed_data + offset, 4);

    if (memcmp(asset_name, asset_filename, ASSETNAME_SIZE) != 0)
    {
      
      offset += 4 + asset_size; // Skip the asset size and the asset content
      continue;
    }

    offset += 4; // Skip the asset size

    asset_content = (uint8_t *)malloc(asset_size);
    if (asset_content == NULL)
    {
      fprintf(stderr, "Failed to allocate memory for the asset content\n");
      free(sealed_data);
      free(unsealed_data);
      return 1;
    }
    memcpy(asset_content, unsealed_data + offset, asset_size);
    
    break;
  }

  /* END */

  if (!write_buf_to_file(asset_filename, asset_content, asset_size, 0))
  {
    fprintf(stderr, "Failed to write the unsealed data to the file\n");
    free(sealed_data);
    return 1;
  }

  // Destroy the enclave
  if ((status = sgx_destroy_enclave(global_eid1)) != SGX_SUCCESS)
  {
    print_error_message(status, "sgx_destroy_enclave");
    return 1;
  }

  return 0;
}

int change_password(const uint8_t *filename, const uint8_t *old_password, const uint8_t *new_password)
{
  sgx_status_t status;
  if (initialize_enclave1() < 0)
  {
    fprintf(stderr, "Error initializing enclave\n");
    return -1;
  }

  uint32_t sealed_size = get_file_size(filename);
  if (sealed_size == -1)
  {
    fprintf(stderr, "The vault file does not exist\n");
    return 1;
  }

  uint8_t *sealed_data = (uint8_t *)malloc(sealed_size);
  if (sealed_data == NULL)
  {
    fprintf(stderr, "Failed to allocate memory for the sealed data\n");
    return 1;
  }

  if (!read_file_to_buf((char *)filename, sealed_data, sealed_size))
  {
    fprintf(stderr, "Failed to read the vault file\n");
    free(sealed_data);
    return 1;
  }

  uint8_t *new_sealed_data = (uint8_t *)malloc(sealed_size);
  if (new_sealed_data == NULL)
  {
    fprintf(stderr, "Failed to allocate memory for the new sealed data\n");
    free(sealed_data);
    return 1;
  }

  int result = 0;
  if ((status = e1_check_password(global_eid1, old_password, PASSWORD_SIZE, sealed_data, sealed_size, &result)) != SGX_SUCCESS)
  {
    print_error_message(status, "check_password");
    free(sealed_data);
    return 1;
  }

  if (!result)
  {
    fprintf(stderr, "The password is incorrect\n");
    free(sealed_data);
    return 1;
  }

  if ((status = e1_change_password(global_eid1, old_password, PASSWORD_SIZE, new_password, PASSWORD_SIZE, sealed_data, sealed_size, new_sealed_data, sealed_size)) != SGX_SUCCESS)
  {
    print_error_message(status, "change_password");
    free(new_sealed_data);
    free(sealed_data);
    return 1;
  }

  if (!write_buf_to_file(filename, new_sealed_data, sealed_size, 0))
  {
    fprintf(stderr, "Failed to write the sealed new vault to the file\n");
    free(sealed_data);
    free(new_sealed_data);
    return 1;
  }

  // Destroy the enclave
  if ((status = sgx_destroy_enclave(global_eid1)) != SGX_SUCCESS)
  {
    print_error_message(status, "sgx_destroy_enclave");
    return 1;
  }

  return 0;
}

int check_asset_integrity(const uint8_t *filename, const uint8_t *password, const uint8_t *asset_filename)
{
  uint32_t asset_size = get_file_size(asset_filename);
  if (asset_size == -1)
  {
    fprintf(stderr, "The asset file does not exist\n");
    return 1;
  }

  uint8_t *asset_data = (uint8_t *)malloc(asset_size);
  if (!read_file_to_buf((char *)asset_filename, asset_data, asset_size))
  {
    fprintf(stderr, "Failed to read the asset file\n");
    free(asset_data);
    return 1;
  }

  sgx_status_t status, ecall_status;
  if (initialize_enclave1() < 0)
  {
    fprintf(stderr, "Error initializing enclave\n");
    return -1;
  }

  uint32_t sealed_size = get_file_size(filename);
  if (sealed_size == -1)
  {
    fprintf(stderr, "The vault file does not exist\n");
    return 1;
  }

  uint8_t *sealed_data = (uint8_t *)malloc(sealed_size);
  if (sealed_data == NULL)
  {
    fprintf(stderr, "Failed to allocate memory for the sealed data\n");
    return 1;
  }

  if (!read_file_to_buf((char *)filename, sealed_data, sealed_size))
  {
    fprintf(stderr, "Failed to read the vault file\n");
    free(sealed_data);
    return 1;
  }

  int result = 0;
  if ((status = e1_check_password(global_eid1, password, PASSWORD_SIZE, sealed_data, sealed_size, &result)) != SGX_SUCCESS)
  {
    print_error_message(status, "check_password");
    free(sealed_data);
    return 1;
  }

  if (!result)
  {
    fprintf(stderr, "The password is incorrect\n");
    free(sealed_data);
    return 1;
  }

  // Get the asset from the vault and calculate the hash (make the get_asset_from_vault function in the enclave)
  uint8_t *asset_vault_hash = (uint8_t *)malloc(SHA256_DIGEST_LENGTH);
  if (asset_vault_hash == NULL)
  {
    fprintf(stderr, "Failed to allocate memory for the asset vault hash\n");
    free(sealed_data);
    return 1;
  }

  if ((status = e1_get_asset_hash_from_vault(global_eid1, asset_filename, ASSETNAME_SIZE, sealed_data, sealed_size, asset_vault_hash, SHA256_DIGEST_LENGTH)) != SGX_SUCCESS)
  {
    print_error_message(status, "get_hash_from_vault");
    free(sealed_data);
    free(asset_vault_hash);
    return 1;
  }

  uint8_t *asset_file_hash = sha256_hash(asset_data, asset_size);

  printf("SHA256(Asset from File): ");
  for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
  {
    printf("%02x", asset_file_hash[i]);
  }
  printf("\n");

  printf("SHA256(Asset from TPDV): ");
  for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
  {
    printf("%02x", asset_vault_hash[i]);
  }
  printf("\n");

  if (memcmp(asset_file_hash, asset_vault_hash, SHA256_DIGEST_LENGTH) != 0)
  {
    fprintf(stderr, "The asset has been tampered with!\n");
    free(sealed_data);
    return 1;
  }

  printf("The asset is intact!\n");

  if ((status = sgx_destroy_enclave(global_eid1)) != SGX_SUCCESS)
  {
    print_error_message(status, "sgx_destroy_enclave");
    return 1;
  }

  return 0;
}

int show_options_menu(void)
{
  int option = 0;

  printf("\033[H\033[J"); // Clear the screen
  printf("                                                                                        (\n");
  printf("  *   )                                                                        (        )\\ )              )                                   (       )  \n");
  printf("` )  /(      )      )               (    (                   (                 )\\ )    (()/     )   ( /(      )     (   (       )     (    )\\   ( /(  \n");
  printf(" ( )(_))  ( /(     (      `  )     ))\\   )(    ___   `  )    )(     (     (   (()/     /(_))   ( /(   )\\())  ( /(     )\\  )\\   ( /(    ))\\  ((_)  )\\()) \n");
  printf("(_(_())   )(_))    )\\  '  /(/(    /((_) (()\\  |___|  /(/(   (()/    )\\    )\\   /(_))   (_))_    )(_)) (_))/   )(_))   ((_)((_)  )(_))  /((_)  _   (_))/  \n");
  printf("|_   _|  ((_)_   _((_))  ((_)_\\  (_))    ((_)       ((_)_\\   ((_)  ((_)  ((_) (_) _|    |   \\  ((_)_  | |_   ((_)_    \\ \\ / /  ((_)_  (_))(  | |  | |_   \n");
  printf("  | |    / _` | | '  \\() | '_ \\) / -_)  | '_|       | '_ \\) | '_| / _ \\ / _ \\  |  _|    | |) | / _` | |  _|  / _` |    \\ V /   / _` | | || | | |  |  _|  \n");
  printf("  |_|    \\__,_| |_|_|_|  | .__/  \\___|  |_|         | .__/  |_|   \\___/ \\___/  |_|      |___/  \\__,_|  \\__|  \\__,_|     \\_/    \\__,_|  \\_,_| |_|   \\__|  \n");
  printf("                         |_|                        |_|                                                                                                  \n");
  printf("|-------------------------------------|\n");
  printf("| 1. Create a new vault               |\n");
  printf("| 2. Add asset to vault               |\n");
  printf("| 3. List all assets in vault         |\n");
  printf("| 4. Retrieve asset from vault        |\n");
  printf("| 5. Check integrity of an asset      |\n");
  printf("| 6. Change password                  |\n");
  printf("| 7. Clone vault                      |\n");
  printf("| 8. Exit                             |\n");
  printf("|-------------------------------------|\n\n");
  printf("Enter your choice: ");

  if (scanf("%d", &option) != 1)
  {
    printf("Error: Invalid input. Please enter a number.\n");
    while (getchar() != '\n') // Clear the input buffer
      ;
    return -1; // Error
  }

  return option;
}

int SGX_CDECL main(int argc, char *argv[])
{
  int option = 0;
  do
  {
    option = show_options_menu();
    getchar(); // Clear the newline character from the input buffer

    switch (option)
    {
    case 1: // Create a new vault
    {
      uint8_t filename[FILENAME_SIZE] = {0}, password[PASSWORD_SIZE] = {0}, creator[CREATOR_SIZE] = {0};

      printf("Enter the vault filename: ");
      if (fgets((char *)filename, FILENAME_SIZE, stdin) == NULL)
      {
        printf("Error: Invalid input. Please enter a string.\n");
        break;
      }

      for (int i = 0; i < FILENAME_SIZE; i++)
      {
        if (filename[i] == '\n')
        {
          filename[i] = '\0';
          break;
        }
      }

      printf("Enter the vault password: ");
      if (fgets((char *)password, PASSWORD_SIZE, stdin) == NULL)
      {
        printf("Error: Invalid input. Please enter a string.\n");
        break;
      }

      for (int i = 0; i < PASSWORD_SIZE; i++)
      {
        if (password[i] == '\n')
        {
          password[i] = '\0';
          break;
        }
      }

      printf("Enter the vault creator: ");
      if (fgets((char *)creator, CREATOR_SIZE, stdin) == NULL)
      {
        printf("Error: Invalid input. Please enter a string.\n");
        break;
      }

      for (int i = 0; i < CREATOR_SIZE; i++)
      {
        if (creator[i] == '\n')
        {
          creator[i] = '\0';
          break;
        }
      }

      printf("\033[H\033[J"); // Clear the screen

      if (create_tpdv(filename, FILENAME_SIZE, password, PASSWORD_SIZE, creator, CREATOR_SIZE) != 0)
      {
        printf("Error: Failed to create the vault.\n");
      }

      printf("Vault created successfully.\n\n");

      printf("Press ENTER to continue...");
      getchar();
      break;
    }
    case 2: // Add asset to vault
    {
      /* LOGIN VERIFICATION */
      uint8_t filename[FILENAME_SIZE] = {0}, password[PASSWORD_SIZE] = {0};

      printf("Enter the vault filename: ");
      if (fgets((char *)filename, FILENAME_SIZE, stdin) == NULL)
      {
        printf("Error: Invalid input. Please enter a string.\n");
        break;
      }

      for (int i = 0; i < FILENAME_SIZE; i++)
      {
        if (filename[i] == '\n')
        {
          filename[i] = '\0';
          break;
        }
      }

      printf("Enter the vault password: ");
      if (fgets((char *)password, PASSWORD_SIZE, stdin) == NULL)
      {
        printf("Error: Invalid input. Please enter a string.\n");
        break;
      }

      for (int i = 0; i < PASSWORD_SIZE; i++)
      {
        if (password[i] == '\n')
        {
          password[i] = '\0';
          break;
        }
      }

      /* ADD ASSET */
      uint8_t asset_filename[ASSETNAME_SIZE] = {0};

      printf("Enter the asset filename: ");
      if (fgets((char *)asset_filename, ASSETNAME_SIZE, stdin) == NULL)
      {
        printf("Error: Invalid input. Please enter a string.\n");
        break;
      }

      for (int i = 0; i < ASSETNAME_SIZE; i++)
      {
        if (asset_filename[i] == '\n')
        {
          asset_filename[i] = '\0';
          break;
        }
      }

      printf("\033[H\033[J"); // Clear the screen

      if (add_asset(filename, password, asset_filename) != 0)
      {
        printf("Error: Failed to add the asset to the vault.\n");
      }

      printf("Asset added successfully.\n\n");

      printf("Press ENTER to continue...");
      getchar();

      break;
    }
    case 3: // FIXME: List all assets in vault (ADD LOGIC TO THE ENCLAVE)
    {
      uint8_t filename[FILENAME_SIZE] = {0}, password[PASSWORD_SIZE] = {0};

      printf("Enter the vault filename: ");
      if (fgets((char *)filename, FILENAME_SIZE, stdin) == NULL)
      {
        printf("Error: Invalid input. Please enter a string.\n");
        break;
      }

      for (int i = 0; i < FILENAME_SIZE; i++)
      {
        if (filename[i] == '\n')
        {
          filename[i] = '\0';
          break;
        }
      }

      printf("Enter the vault password: ");
      if (fgets((char *)password, PASSWORD_SIZE, stdin) == NULL)
      {
        printf("Error: Invalid input. Please enter a string.\n");
        break;
      }

      for (int i = 0; i < PASSWORD_SIZE; i++)
      {
        if (password[i] == '\n')
        {
          password[i] = '\0';
          break;
        }
      }

      printf("\033[H\033[J"); // Clear the screen

      if (list_all_assets(filename, password) != 0)
      {
        printf("Error: Failed to list all assets in the vault.\n");
      }

      printf("Press ENTER to continue...");
      getchar();

      break;
    }
    case 4: // FIXME: Retrieve asset from vault (ADD LOGIC TO THE ENCLAVE)
    {
      uint8_t filename[FILENAME_SIZE] = {0}, password[PASSWORD_SIZE] = {0};

      printf("Enter the vault filename: ");
      if (fgets((char *)filename, FILENAME_SIZE, stdin) == NULL)
      {
        printf("Error: Invalid input. Please enter a string.\n");
        break;
      }

      for (int i = 0; i < FILENAME_SIZE; i++)
      {
        if (filename[i] == '\n')
        {
          filename[i] = '\0';
          break;
        }
      }

      printf("Enter the vault password: ");
      if (fgets((char *)password, PASSWORD_SIZE, stdin) == NULL)
      {
        printf("Error: Invalid input. Please enter a string.\n");
        break;
      }

      for (int i = 0; i < PASSWORD_SIZE; i++)
      {
        if (password[i] == '\n')
        {
          password[i] = '\0';
          break;
        }
      }

      printf("\033[H\033[J"); // Clear the screen

      uint8_t asset_filename[ASSETNAME_SIZE] = {0};

      printf("Enter the asset filename: ");
      if (fgets((char *)asset_filename, ASSETNAME_SIZE, stdin) == NULL)
      {
        printf("Error: Invalid input. Please enter a string.\n");
        break;
      }

      for (int i = 0; i < ASSETNAME_SIZE; i++)
      {
        if (asset_filename[i] == '\n')
        {
          asset_filename[i] = '\0';
          break;
        }
      }

      printf("\033[H\033[J"); // Clear the screen

      if (retrieve_asset(filename, password, asset_filename) != 0)
      {
        printf("Error: Failed to list retrieve asset from the vault.\n");
      }

      printf("Asset retrieved successfully.\n\n");

      printf("Press ENTER to continue...");
      getchar();

      break;
    }
    case 5: // Check integrity of an asset
    {
      // (Calculate the hash of the asset and calculate the asset of the content in the vault and compare them)
      uint8_t filename[FILENAME_SIZE] = {0}, password[PASSWORD_SIZE] = {0}, asset_filename[ASSETNAME_SIZE] = {0};

      printf("Enter the filename: ");
      if (fgets((char *)filename, FILENAME_SIZE, stdin) == NULL)
      {
        printf("Error: Invalid input. Please enter a string.\n");
        break;
      }

      for (int i = 0; i < FILENAME_SIZE; i++)
      {
        if (filename[i] == '\n')
        {
          filename[i] = '\0';
          break;
        }
      }

      printf("Enter the password: ");
      if (fgets((char *)password, PASSWORD_SIZE, stdin) == NULL)
      {
        printf("Error: Invalid input. Please enter a string.\n");
        break;
      }

      for (int i = 0; i < PASSWORD_SIZE; i++)
      {
        if (password[i] == '\n')
        {
          password[i] = '\0';
          break;
        }
      }

      printf("Enter the asset filename: ");
      if (fgets((char *)asset_filename, ASSETNAME_SIZE, stdin) == NULL)
      {
        printf("Error: Invalid input. Please enter a string.\n");
        break;
      }

      for (int i = 0; i < ASSETNAME_SIZE; i++)
      {
        if (asset_filename[i] == '\n')
        {
          asset_filename[i] = '\0';
          break;
        }
      }

      printf("\033[H\033[J"); // Clear the screen
      if (check_asset_integrity(filename, password, asset_filename) != 0)
      {
        printf("Error: Failed to check the integrity of the asset.\n");
      }

      printf("Press ENTER to continue...");
      getchar();

      break;
    }
    case 6: // Password change
    {
      uint8_t filename[FILENAME_SIZE] = {0}, old_password[PASSWORD_SIZE] = {0}, confirm_old_password[PASSWORD_SIZE] = {0}, new_password[PASSWORD_SIZE] = {0};

      printf("Enter the vault filename: ");
      if (fgets((char *)filename, FILENAME_SIZE, stdin) == NULL)
      {
        printf("Error: Invalid input. Please enter a string.\n");
        break;
      }

      for (int i = 0; i < FILENAME_SIZE; i++)
      {
        if (filename[i] == '\n')
        {
          filename[i] = '\0';
          break;
        }
      }

      printf("Enter the old vault password: ");
      if (fgets((char *)old_password, PASSWORD_SIZE, stdin) == NULL)
      {
        printf("Error: Invalid input. Please enter a string.\n");
        break;
      }

      for (int i = 0; i < PASSWORD_SIZE; i++)
      {
        if (old_password[i] == '\n')
        {
          old_password[i] = '\0';
          break;
        }
      }

      printf("Confirm the old vault password: ");
      if (fgets((char *)confirm_old_password, PASSWORD_SIZE, stdin) == NULL)
      {
        printf("Error: Invalid input. Please enter a string.\n");
        break;
      }

      for (int i = 0; i < PASSWORD_SIZE; i++)
      {
        if (confirm_old_password[i] == '\n')
        {
          confirm_old_password[i] = '\0';
          break;
        }
      }

      if (memcmp(old_password, confirm_old_password, PASSWORD_SIZE) != 0)
      {
        printf("Error: The passwords do not match.\n");
        break;
      }

      printf("Enter the new vault password: ");
      if (fgets((char *)new_password, PASSWORD_SIZE, stdin) == NULL)
      {
        printf("Error: Invalid input. Please enter a string.\n");
        break;
      }

      for (int i = 0; i < PASSWORD_SIZE; i++)
      {
        if (new_password[i] == '\n')
        {
          new_password[i] = '\0';
          break;
        }
      }

      printf("\033[H\033[J"); // Clear the screen
      if (change_password(filename, old_password, new_password) != 0)
      {
        printf("Error: Failed to change the password.\n");
      }

      printf("Password changed successfully.\n\n");

      printf("Press ENTER to continue...");
      getchar();

      break;
    }
    case 7: // TODO: Clone vault
    {
      printf("Clone vault\n");
      break;
    }
    case 8: // Exit
    {
      printf("\033[H\033[J"); // Clear the screen
      printf("Exiting...\n");
      break;
    }
    default:
      printf("Invalid option\n");
      break;
    }
  } while (option != 8);

  return 0;
}