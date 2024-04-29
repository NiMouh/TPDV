/*
 * Copyright (C) 2011-2018 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include <time.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <iostream>
#include <fstream>

#include "sgx_urts.h"
#include "App.h"
#include "Enclave1_u.h"

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
  size_t ttl = sizeof(sgx_errlist) / sizeof(sgx_errlist[0]);
  size_t idx;

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

static size_t get_file_size(const char *filename)
{
  std::ifstream ifs(filename, std::ios::in | std::ios::binary);
  if (!ifs.good())
  {
    std::cout << "Failed to open the file \"" << filename << "\"" << std::endl;
    return -1;
  }
  ifs.seekg(0, std::ios::end);
  size_t size = (size_t)ifs.tellg();
  return size;
}

static bool read_file_to_buf(const char *filename, uint8_t *buf, size_t bsize)
{
  if (filename == NULL || buf == NULL || bsize == 0)
    return false;
  std::ifstream ifs(filename, std::ios::binary | std::ios::in);
  if (!ifs.good())
  {
    std::cout << "Failed to open the file \"" << filename << "\"" << std::endl;
    return false;
  }
  ifs.read(reinterpret_cast<char *>(buf), bsize);
  if (ifs.fail())
  {
    std::cout << "Failed to read the file \"" << filename << "\"" << std::endl;
    return false;
  }
  return true;
}

static bool write_buf_to_file(const char *filename, const uint8_t *buf, size_t bsize, long offset)
{
  if (filename == NULL || buf == NULL || bsize == 0)
    return false;
  std::ofstream ofs(filename, std::ios::binary | std::ios::out);
  if (!ofs.good())
  {
    std::cout << "Failed to open the file \"" << filename << "\"" << std::endl;
    return false;
  }
  ofs.seekp(offset, std::ios::beg);
  ofs.write(reinterpret_cast<const char *>(buf), bsize);
  if (ofs.fail())
  {
    std::cout << "Failed to write the file \"" << filename << "\"" << std::endl;
    return false;
  }

  return true;
}

int create_tpdv(uint8_t *filename, size_t filename_size, uint8_t *password, size_t password_size, uint8_t *creator, size_t creator_size)
{

  if (initialize_enclave1() < 0)
  {
    fprintf(stderr, "Error initializing enclave\n");
    return -1;
  }

  sgx_status_t status;

  uint8_t header[HEADER_SIZE] = {0}; // Create the header (filename + password + creator)
  memcpy(header, filename, filename_size);
  memcpy(header + filename_size, password, password_size);
  memcpy(header + filename_size + password_size, creator, creator_size);

  size_t sealed_size = sizeof(sgx_sealed_data_t) + HEADER_SIZE;
  uint8_t *sealed_data = (uint8_t *)malloc(sealed_size);

  sgx_status_t ecall_status;
  if ((status = seal(global_eid1, &ecall_status, header, HEADER_SIZE, (sgx_sealed_data_t *)sealed_data, sealed_size)) != SGX_SUCCESS)
  {
    print_error_message(status, "seal");
    free(sealed_data);
    return 1;
  }

  if (!write_buf_to_file((char *)filename, sealed_data, sealed_size, 0))
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

int check_tpdv(const uint8_t *filename, size_t filename_size, const uint8_t *password, size_t password_size)
{
  if (initialize_enclave1() < 0)
    return -1; // Error initializing enclave

  sgx_status_t status;

  size_t sealed_size = get_file_size((char *)filename);
  if (sealed_size == -1)
    return 1;

  uint8_t *sealed_data = (uint8_t *)malloc(sealed_size);
  if (!read_file_to_buf((char *)filename, sealed_data, sealed_size))
  {
    std::cout << "Failed to read the sealed data from the file" << std::endl;
    free(sealed_data);
    return 1;
  }

  uint8_t header[HEADER_SIZE] = {0};
  sgx_status_t ecall_status;
  if ((status = unseal(global_eid1, &ecall_status, (sgx_sealed_data_t *)sealed_data, sealed_size, header, HEADER_SIZE)) != SGX_SUCCESS)
  {
    print_error_message(status, "unseal");
    free(sealed_data);
    return 1;
  }

  if (memcmp(header + FILENAME_SIZE, password, password_size) != 0)
  {
    std::cout << "The password is incorrect" << std::endl;
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

int add_asset(const uint8_t *asset_filename)
{
  if (initialize_enclave1() < 0)
  {
    fprintf(stderr, "Error initializing enclave\n");
    return -1;
  }

  // Open asset file (binary file) and read its content
  size_t asset_size = get_file_size((char *)asset_filename);
  if (asset_size == -1)
  {
    fprintf(stderr, "Failed to open the asset file\n");
    return 1;
  }

  uint8_t *asset_data = (uint8_t *)malloc(asset_size);
  if (!read_file_to_buf((char *)asset_filename, asset_data, asset_size))
  {
    fprintf(stderr, "Failed to read the asset file\n");
    free(asset_data);
    return 1;
  }

  // Read the vault file and unseal it
  size_t sealed_size = get_file_size((char *)filename);
  if (sealed_size == -1)
  {
    fprintf(stderr, "Failed to open the vault file\n");
    free(asset_data);
    free(sealed_data);
    return 1;
  }

  uint8_t *sealed_data = (uint8_t *)malloc(sealed_size);
  if (!read_file_to_buf((char *)filename, sealed_data, sealed_size))
  {
    fprintf(stderr, "Failed to read the vault file\n");
    free(asset_data);
    free(sealed_data);
    return 1;
  }

  // FIXME: Unseal the vault (he could have assets) have a efficient way to check the vault size
  uint8_t vault[TPDV_SIZE] = {0};
  sgx_status_t ecall_status;
  if ((status = unseal(global_eid1, &ecall_status, (sgx_sealed_data_t *)sealed_data, sealed_size, vault, TPDV_SIZE)) != SGX_SUCCESS)
  {
    print_error_message(status, "unseal");
    free(asset_data);
    free(sealed_data);
    return 1;
  }

  if (ecall_status != 0) // Tampered vault
  {
    fprintf(stderr, "The vault is tampered\n");
    free(asset_data);
    free(sealed_data);
    return 1;
  }

  uint16_t *number_of_assets = (uint16_t *)(vault + HEADER_SIZE);

  // If it's full, return an error
  if (*number_of_assets == MAX_ASSETS)
  {
    fprintf(stderr, "The vault is full\n");
    free(asset_data);
    free(sealed_data);
    return 1;
  }

  // TODO: If it's zero, hash the asset and save the last 4 bytes after the number of assets, and then add the asset
  

  // TODO: If not, add the asset to the end of the vault, hash all the assets and save the last 4 bytes after the number of assets


  // TODO: Seal the vault and save it to the file

  // Destroy the enclave
  if ((status = sgx_destroy_enclave(global_eid1)) != SGX_SUCCESS)
  {
    print_error_message(status, "sgx_destroy_enclave");
    return 1;
  }

  free(asset_data);
  free(sealed_data);

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

    switch (option)
    {
    case 1: // Create a new vault
    {
      uint8_t filename[FILENAME_SIZE], password[PASSWORD_SIZE], creator[CREATOR_SIZE];

      printf("Enter the filename: ");
      if (scanf("%s", (char *)filename) != 1)
      {
        printf("Error: Invalid input. Please enter a string.\n");
        break;
      }

      printf("Enter the password: ");
      if (scanf("%s", (char *)password) != 1)
      {
        printf("Error: Invalid input. Please enter a string.\n");
        break;
      }

      printf("Enter the creator: ");
      if (scanf("%s", (char *)creator) != 1)
      {
        printf("Error: Invalid input. Please enter a string.\n");
        break;
      }

      size_t filename_size = strlen((char *)filename);
      size_t password_size = strlen((char *)password);
      size_t creator_size = strlen((char *)creator);

      if (filename_size > FILENAME_SIZE || password_size > PASSWORD_SIZE || creator_size > CREATOR_SIZE)
      {
        printf("Error: The filename, password, or creator is too long.\n");
        break;
      }

      if (create_tpdv(filename, filename_size, password, password_size, creator, creator_size) != 0)
      {
        printf("Error: Failed to create the vault.\n");
        break;
      }

      printf("Vault created successfully.\n");
      break;
    }
    case 2: // FIXME: Add asset to vault
    {
      // Ask for vault filename and password
      uint8_t filename[FILENAME_SIZE], password[PASSWORD_SIZE];
      printf("Enter the filename: ");
      if (scanf("%s", (char *)filename) != 1)
      {
        printf("Error: Invalid input. Please enter a string.\n");
        break;
      }

      printf("Enter the password: ");
      if (scanf("%s", (char *)password) != 1)
      {
        printf("Error: Invalid input. Please enter a string.\n");
        break;
      }

      size_t filename_size = strlen((char *)filename);
      size_t password_size = strlen((char *)password);

      if (filename_size > FILENAME_SIZE || password_size > PASSWORD_SIZE)
      {
        printf("Error: The filename or password is too long.\n");
        break;
      }

      // Check if the vault exists and the password is correct
      if (check_tpdv(filename, filename_size, password, password_size) != 0)
      {
        printf("Error: The vault does not exist or the password is incorrect.\n");
        break;
      }

      // Add asset to vault
      uint8_t asset_filename[ASSETNAME_SIZE];

      printf("Enter the asset filename: ");
      if (scanf("%s", (char *)asset_filename) != 1)
      {
        printf("Error: Invalid input. Please enter a string.\n");
        break;
      }

      size_t asset_filename_size = strlen((char *)asset_filename);
      if (asset_filename_size > ASSETNAME_SIZE)
      {
        printf("Error: The asset filename is too long.\n");
        break;
      }

      if (add_asset(asset_filename) != 0)
      {
        printf("Error: Failed to add the asset to the vault.\n");
        break;
      }



      break;
    }
    case 3: // TODO: List all assets in vault
      printf("List all assets in vault\n");
      break;
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