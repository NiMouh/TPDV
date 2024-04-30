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

  uint32_t unsealed_size = 0;
  sgx_status_t status, ecall_status;
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

  // Check if the password is correct
  if (strcmp((char *)password, (char *)unsealed_data + FILENAME_SIZE) != 0)
  {
    fprintf(stderr, "The password is incorrect\n");
    free(sealed_data);
    free(unsealed_data);
    return 1;
  }

  // Check how many assets are in the vault
  uint32_t number_of_assets = 0;
  memcpy(&number_of_assets, unsealed_data + FILENAME_SIZE + PASSWORD_SIZE + CREATOR_SIZE, ASSETS_SIZE);

  if (number_of_assets >= MAX_ASSETS)
  {
    fprintf(stderr, "The vault is full\n");
    free(sealed_data);
    free(unsealed_data);
    return 1;
  }

  // Declare the new vault with the new asset (size of old vault + asset name size + size of the asset + asset size)
  uint32_t new_vault_size = unsealed_size + ASSETNAME_SIZE + 4 + asset_size;
  uint8_t *new_vault = (uint8_t *)malloc(new_vault_size);

  // Copy the old vault to the new vault
  memcpy(new_vault, unsealed_data, unsealed_size);

  // Append the asset name to the new vault
  memcpy(new_vault + unsealed_size, asset_filename, ASSETNAME_SIZE);

  // Append the asset size to the new vault
  memcpy(new_vault + unsealed_size + ASSETNAME_SIZE, &asset_size, 4);

  // Append the asset to the new vault
  memcpy(new_vault + unsealed_size + ASSETNAME_SIZE + 4, asset_data, asset_size);

  // Increment the number of assets and update the new vault
  number_of_assets++;
  memcpy(new_vault + FILENAME_SIZE + PASSWORD_SIZE + CREATOR_SIZE, &number_of_assets, ASSETS_SIZE);

  // Hash the assets using openssl
  uint8_t *hash_result = sha256_hash(new_vault + HEADER_SIZE, new_vault_size - HEADER_SIZE);
  if (hash_result == NULL)
  {
    fprintf(stderr, "Failed to hash the assets\n");
    free(sealed_data);
    free(unsealed_data);
    free(new_vault);
    free(asset_data);
    return 1;
  }

  uint32_t nonce = 0;

  // Add the last 4 bytes of the hash to the nonce
  memcpy(&nonce, hash_result + SHA256_DIGEST_LENGTH - 4, 4);

  // Update the new vault with the nonce
  memcpy(new_vault + HEADER_SIZE - NONCE_SIZE, &nonce, NONCE_SIZE);

  // Print the nonce
  printf("Nonce: %u\n", nonce);

  // Print the number of assets
  printf("Number of assets: %u\n", number_of_assets);

  // Print the new vault
  for (int i = 0; i < new_vault_size; i++)
  {
    if (new_vault[i] == '\0')
      printf("\\0");
    if (new_vault[i] == '\n')
      printf("\\n");
    else
      printf("%c", new_vault[i]);
  }
  printf("\n");

  // Get the size of the sealed new vault
  if ((status = get_sealed_data_size(global_eid1, &sealed_size, new_vault_size)) != SGX_SUCCESS)
  {
    print_error_message(status, "get_sealed_data_size");
    free(sealed_data);
    free(unsealed_data);
    free(new_vault);
    free(asset_data);
    return 1;
  }

  // Allocate memory for the sealed new vault
  sealed_data = (uint8_t *)malloc(sealed_size);
  if (sealed_data == NULL)
  {
    fprintf(stderr, "Failed to allocate memory for the sealed new vault\n");
    free(sealed_data);
    free(unsealed_data);
    free(new_vault);
    free(asset_data);
    return 1;
  }

  // Seal the new vault
  if ((status = seal(global_eid1, &ecall_status, new_vault, new_vault_size, (sgx_sealed_data_t *)sealed_data, sealed_size)) != SGX_SUCCESS)
  {
    print_error_message(status, "seal");
    free(sealed_data);
    free(unsealed_data);
    free(new_vault);
    free(asset_data);
    return 1;
  }

  // Save the sealed new vault to the file
  if (!write_buf_to_file(filename, sealed_data, sealed_size, 0))
  {
    fprintf(stderr, "Failed to write the sealed new vault to the file\n");
    free(sealed_data);
    free(unsealed_data);
    free(new_vault);
    free(asset_data);
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

int list_all_assets(const uint8_t *filename, const uint8_t *password)
{
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

  uint32_t unsealed_size = 0;
  sgx_status_t status, ecall_status;
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

  // Check if the password is correct
  if (strcmp((char *)password, (char *)unsealed_data + FILENAME_SIZE) != 0)
  {
    fprintf(stderr, "The password is incorrect\n");
    free(sealed_data);
    free(unsealed_data);
    return 1;
  }

  // Check how many assets are in the vault
  uint32_t number_of_assets = 0;
  memcpy(&number_of_assets, unsealed_data + FILENAME_SIZE + PASSWORD_SIZE + CREATOR_SIZE, ASSETS_SIZE);

  if (number_of_assets == 0)
  {
    fprintf(stderr, "The vault is empty\n");
    free(sealed_data);
    free(unsealed_data);
    return 1;
  }

  // Print all the assets names, size and content
  for (int i = 0; i < (int)number_of_assets; i++)
  {
    // Get the asset name
    uint8_t asset_name[ASSETNAME_SIZE] = {0};
    memcpy(asset_name, unsealed_data + HEADER_SIZE + i * (ASSETNAME_SIZE + 4), ASSETNAME_SIZE);

    // Get the asset size
    uint32_t asset_size = 0;
    memcpy(&asset_size, unsealed_data + HEADER_SIZE + i * (ASSETNAME_SIZE + 4) + ASSETNAME_SIZE, 4);

    // Get the asset content
    uint8_t asset_content[asset_size];
    memcpy(asset_content, unsealed_data + HEADER_SIZE + i * (ASSETNAME_SIZE + 4) + ASSETNAME_SIZE + 4, asset_size);

    // Print the asset name
    printf("Asset name: ");
    for (int j = 0; j < ASSETNAME_SIZE; j++)
    {
      if (asset_name[j] == '\0')
        printf("\\0");
      if (asset_name[j] == '\n')
        printf("\\n");
      else
        printf("%c", asset_name[j]);
    }
    printf("\n");

    // Print the asset size
    printf("Asset size: %u\n", asset_size);

    // Print the asset content
    printf("Asset content: ");
    for (int j = 0; j < asset_size; j++)
    {
      if (asset_content[j] == '\0')
        printf("\\0");
      if (asset_content[j] == '\n')
        printf("\\n");
      else
        printf("%c", asset_content[j]);
    }
    printf("\n");
  }

  // Destroy the enclave
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
  printf("Tamper-proof Digital Vault\n");
  printf("  1: Create a new vault\n");
  printf("  2: Add asset to vault\n");
  printf("  3: List all assets in vault\n");
  printf("  4: Retrieve asset from vault\n");
  printf("  5: Check integrity of vault\n");
  printf("  6: Password change\n");
  printf("  7: Clone vault\n");
  printf("  8: Exit\n");
  printf("Enter option: ");

  // Check if scanf successfully read an integer
  if (scanf("%d", &option) != 1)
  {
    printf("Error: Invalid input. Please enter a number.\n");
    // Clear input buffer
    while (getchar() != '\n')
      ;
    // Return a special value indicating an error
    return -1;
  }

  return option;
}

int SGX_CDECL main(int argc, char *argv[])
{
  int option = 0;
  sgx_status_t status;

  do
  {
    option = show_options_menu();
    getchar(); // Clear the newline character from the input buffer

    switch (option)
    {
    case 1: // Create a new vault
    {
      uint8_t filename[FILENAME_SIZE] = {0}, password[PASSWORD_SIZE] = {0}, creator[CREATOR_SIZE] = {0};

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

      printf("Enter the creator: ");
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

      if (create_tpdv(filename, FILENAME_SIZE, password, PASSWORD_SIZE, creator, CREATOR_SIZE) != 0)
      {
        printf("Error: Failed to create the vault.\n");
      }

      printf("Vault created successfully.\n");
      break;
    }
    case 2: // Add asset to vault
    {
      /* LOGIN VERIFICATION */
      uint8_t filename[FILENAME_SIZE] = {0}, password[PASSWORD_SIZE] = {0};

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

      if (add_asset(filename, password, asset_filename) != 0)
      {
        printf("Error: Failed to add the asset to the vault.\n");
      }

      break;
    }
    case 3: // List all assets in vault
    {
      uint8_t filename[FILENAME_SIZE] = {0}, password[PASSWORD_SIZE] = {0};

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

      if (list_all_assets(filename, password) != 0)
      {
        printf("Error: Failed to list all assets in the vault.\n");
      }
      break;
    }
    case 4: // TODO: Retrieve asset from vault
      printf("Retrieve asset from vault\n");
      break;
    case 5: // TODO: Check integrity of vault
      printf("Check integrity of vault\n");
      break;
    case 6: // TODO: Password change
      printf("Password change\n");
      break;
    case 7: // TODO: Clone vault
      printf("Clone vault\n");
      break;
    case 8:
      printf("Exiting...\n");
      break;
    default:
      printf("Invalid option\n");
      break;
    }
  } while (option != 8);

  return 0;
}