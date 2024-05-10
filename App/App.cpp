/**
 * @file App.cpp
 *
 * @brief Application file for the TPDV system
 *
 * This file contains the main application logic for the TPDV system using Intel SGX.
 *
 * @author Simão Andrade (118345)
 *         João Almeida (118340)
 */

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
#include "Enclave2_u.h"

/*
 * Error reporting
 */

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
 * Enclave1 stuff
 */

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

/*
 * Enclave2 stuff
 */

int initialize_enclave2(void)
{
  sgx_status_t ret;

  if ((ret = sgx_create_enclave(ENCLAVE2_FILENAME, SGX_DEBUG_FLAG, NULL, NULL, &global_eid2, NULL)) != SGX_SUCCESS)
  {
    print_error_message(ret, "sgx_create_enclave (enclave2)");
    return -1;
  }
  return 0;
}

void ocall_e2_print_string(const char *str)
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
  ifs.close();

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

/* HASHING FUNCTIONS */

uint8_t *sha256_hash(const uint8_t *data, uint32_t data_len)
{
  uint8_t *hash_result = (uint8_t *)malloc(SHA256_DIGEST_LENGTH);
  if (!hash_result)
  {
    return NULL;
  }

  EVP_MD_CTX *mdctx;
  const EVP_MD *md;
  unsigned int md_len;

  mdctx = EVP_MD_CTX_new(); // Create a new context
  if (mdctx == NULL)
  {
    free(hash_result);
    return NULL;
  }

  md = EVP_sha256(); // SHA-256 digest type

  if (1 != EVP_DigestInit_ex(mdctx, md, NULL))
  {
    EVP_MD_CTX_free(mdctx);
    free(hash_result);
    return NULL;
  }

  if (1 != EVP_DigestUpdate(mdctx, data, data_len))
  {
    EVP_MD_CTX_free(mdctx);
    free(hash_result);
    return NULL;
  }

  if (1 != EVP_DigestFinal_ex(mdctx, hash_result, &md_len))
  {
    EVP_MD_CTX_free(mdctx);
    free(hash_result);
    return NULL;
  }

  EVP_MD_CTX_free(mdctx);

  return hash_result;
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
  if ((status = e1_check_nonce(global_eid1, sealed_data, sealed_size, &result)) != SGX_SUCCESS)
  {
    print_error_message(status, "check_nonce");
    free(sealed_data);
    return 1;
  }

  if (!result)
  {
    fprintf(stderr, "The integrity of the vault has been compromised\n");
    free(sealed_data);
    return 1;
  }

  if ((status = e1_check_password(global_eid1, password, PASSWORD_SIZE, sealed_data, sealed_size, &result)) != SGX_SUCCESS)
  {
    print_error_message(status, "check_password");
    free(sealed_data);
    return 1;
  }

  if (!result)
  {
    fprintf(stderr, "The credentials are invalid\n");
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
  if ((status = e1_check_nonce(global_eid1, sealed_data, sealed_size, &result)) != SGX_SUCCESS)
  {
    print_error_message(status, "check_nonce");
    free(sealed_data);
    return 1;
  }

  if (!result)
  {
    fprintf(stderr, "The integrity of the vault has been compromised\n");
    free(sealed_data);
    return 1;
  }

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

  if ((status = e1_list_all_assets(global_eid1, sealed_data, sealed_size)) != SGX_SUCCESS)
  {
    print_error_message(status, "list_all_assets");
    free(sealed_data);
    return 1;
  }

  if ((status = sgx_destroy_enclave(global_eid1)) != SGX_SUCCESS)
  {
    print_error_message(status, "sgx_destroy_enclave");
    return 1;
  }

  return 0;
}

int list_all_assets2(const uint8_t *filename, const uint8_t *password)
{
  sgx_status_t status;
  if (initialize_enclave2() < 0)
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
  if ((status = e2_check_password(global_eid2, password, PASSWORD_SIZE, sealed_data, sealed_size, &result)) != SGX_SUCCESS)
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

  if ((status = e2_list_all_assets(global_eid2, sealed_data, sealed_size)) != SGX_SUCCESS)
  {
    print_error_message(status, "list_all_assets");
    free(sealed_data);
    return 1;
  }

  if ((status = sgx_destroy_enclave(global_eid2)) != SGX_SUCCESS)
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
  if ((status = e1_check_nonce(global_eid1, sealed_data, sealed_size, &result)) != SGX_SUCCESS)
  {
    print_error_message(status, "check_nonce");
    free(sealed_data);
    return 1;
  }

  if (!result)
  {
    fprintf(stderr, "The integrity of the vault has been compromised\n");
    free(sealed_data);
    return 1;
  }

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

  uint32_t asset_size = 0;
  if ((status = e1_get_asset_size(global_eid1, asset_filename, ASSETNAME_SIZE, sealed_data, sealed_size, &asset_size)) != SGX_SUCCESS)
  {
    print_error_message(status, "get_asset_size");
    free(sealed_data);
    return 1;
  }

  uint8_t *asset_content = (uint8_t *)malloc(asset_size);
  if (asset_content == NULL)
  {
    fprintf(stderr, "Failed to allocate memory for the asset content\n");
    free(sealed_data);
    return 1;
  }

  if ((status = e1_retrieve_asset(global_eid1, asset_filename, ASSETNAME_SIZE, sealed_data, sealed_size, asset_content, asset_size)) != SGX_SUCCESS)
  {
    print_error_message(status, "retrieve_asset");
    free(sealed_data);
    free(asset_content);
    return 1;
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
  if ((status = e1_check_nonce(global_eid1, sealed_data, sealed_size, &result)) != SGX_SUCCESS)
  {
    print_error_message(status, "check_nonce");
    free(sealed_data);
    return 1;
  }

  if (!result)
  {
    fprintf(stderr, "The integrity of the vault has been compromised\n");
    free(sealed_data);
    return 1;
  }

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
  if ((status = e1_check_nonce(global_eid1, sealed_data, sealed_size, &result)) != SGX_SUCCESS)
  {
    print_error_message(status, "check_nonce");
    free(sealed_data);
    return 1;
  }

  if (!result)
  {
    fprintf(stderr, "The integrity of the vault has been compromised\n");
    free(sealed_data);
    return 1;
  }

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
  }

  printf("The asset is intact!\n");

  if ((status = sgx_destroy_enclave(global_eid1)) != SGX_SUCCESS)
  {
    print_error_message(status, "sgx_destroy_enclave");
    return 1;
  }

  return 0;
}

int clone_tpdv(const uint8_t *original_tpdv, const uint8_t *original_password, const uint8_t *cloned_tpdv, const uint8_t *cloned_password)
{
  sgx_status_t status, dh_status;
  sgx_dh_msg1_t msg1;
  sgx_dh_msg2_t msg2;
  sgx_dh_msg3_t msg3;

  if (initialize_enclave1() < 0)
  {
    fprintf(stderr, "Error initializing enclave\n");
    return -1;
  }

  if (initialize_enclave2() < 0)
  {
    fprintf(stderr, "Error initializing enclave\n");
    return -1;
  }

  uint32_t sealed_size = get_file_size(original_tpdv);
  if (sealed_size == -1)
  {
    fprintf(stderr, "The vault file does not exist\n");
    return 1;
  }

  uint8_t sealed_data[sealed_size] = {0};

  if (!read_file_to_buf((char *)original_tpdv, sealed_data, sealed_size))
  {
    fprintf(stderr, "Failed to read the vault file\n");
    return 1;
  }

  int result = 0;
  if ((status = e1_check_nonce(global_eid1, sealed_data, sealed_size, &result)) != SGX_SUCCESS)
  {
    print_error_message(status, "check_nonce");
    return 1;
  }

  if (!result)
  {
    fprintf(stderr, "The integrity of the vault has been compromised\n");
    return 1;
  }

  if ((status = e1_check_password(global_eid1, original_password, PASSWORD_SIZE, sealed_data, sealed_size, &result)) != SGX_SUCCESS)
  {
    print_error_message(status, "check_password");
    return 1;
  }

  if (!result)
  {
    fprintf(stderr, "The password is incorrect\n");
    return 1;
  }

  // Start the key exchange (diffie-hellman)
  if ((status = e1_init_session(global_eid1, &dh_status)) != SGX_SUCCESS || dh_status != SGX_SUCCESS)
  {
    print_error_message((status != SGX_SUCCESS) ? status : dh_status, "e1_init_session");
    return 1;
  }

  if ((status = e2_init_session(global_eid2, &dh_status)) != SGX_SUCCESS || dh_status != SGX_SUCCESS)
  {
    print_error_message((status != SGX_SUCCESS) ? status : dh_status, "e2_init_session");
    return 1;
  }

  if ((status = e2_create_message1(global_eid2, &msg1, &dh_status)) != SGX_SUCCESS || dh_status != SGX_SUCCESS)
  {
    print_error_message((status != SGX_SUCCESS) ? status : dh_status, "e2_create_message1");
    return 1;
  }

  if ((status = e1_process_message1(global_eid1, &msg1, &msg2, &dh_status)) != SGX_SUCCESS || dh_status != SGX_SUCCESS)
  {
    print_error_message((status != SGX_SUCCESS) ? status : dh_status, "e1_process_message1");
    return 1;
  }

  if ((status = e2_process_message2(global_eid2, &msg2, &msg3, &dh_status)) != SGX_SUCCESS || dh_status != SGX_SUCCESS)
  {
    print_error_message((status != SGX_SUCCESS) ? status : dh_status, "e2_process_message2");
    return 1;
  }

  if ((status = e1_process_message3(global_eid1, &msg3, &dh_status)) != SGX_SUCCESS || dh_status != SGX_SUCCESS)
  {
    print_error_message((status != SGX_SUCCESS) ? status : dh_status, "e1_process_message3");
    return 1;
  }

  // Get the unsealed size to declare the ciphertext
  uint32_t ciphertext_size = 0;
  if ((status = get_unsealed_data_size(global_eid1, &ciphertext_size, sealed_data, sealed_size)) != SGX_SUCCESS)
  {
    print_error_message(status, "get_unsealed_data_size");
    return 1;
  }

  uint8_t ciphertext[ciphertext_size] = {0};

  // Declare function that unseales and encrypts the data
  if ((status = e1_unseal_and_cipher(global_eid1, sealed_data, sealed_size, ciphertext, ciphertext_size)) != SGX_SUCCESS)
  {
    print_error_message(status, "e1_unseal_and_cipher");
    return 1;
  }

  // Declare function that decrypts and seals the data
  if ((status = e2_decipher_and_seal(global_eid2, ciphertext, ciphertext_size, cloned_password, PASSWORD_SIZE, sealed_data, sealed_size)) != SGX_SUCCESS)
  {
    print_error_message(status, "e2_decipher_and_seal");
    return 1;
  }

  // Write the new sealed data to the cloned tpdv
  if (!write_buf_to_file(cloned_tpdv, sealed_data, sealed_size, 0))
  {
    fprintf(stderr, "Failed to write the sealed new vault to the file\n");
    return 1;
  }

  if ((status = sgx_destroy_enclave(global_eid1)) != SGX_SUCCESS)
  {
    print_error_message(status, "sgx_destroy_enclave");
    return 1;
  }

  if ((status = sgx_destroy_enclave(global_eid2)) != SGX_SUCCESS)
  {
    print_error_message(status, "sgx_destroy_enclave");
    return 1;
  }

  return 0;
}

/* MENU FUNCTIONS*/

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
    case 3: // List all assets in vault
    {
      uint8_t filename[FILENAME_SIZE] = {0}, password[PASSWORD_SIZE] = {0};
      int choosen_enclave = 1;

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

      // Choose the enclave and wait for the user to press ENTER
      printf("Choose the enclave to list the assets (default is enclave 1): ");
      if (scanf("%d", &choosen_enclave) != 1)
      {
        printf("Error: Invalid input. Please enter a number.\n");
        while (getchar() != '\n') // Clear the input buffer
          ;
        break;
      }
      getchar(); // Clear the newline character from the input buffer

      printf("\033[H\033[J"); // Clear the screen

      if (choosen_enclave == 2)
      {
        if (list_all_assets2(filename, password) != 0)
        {
          printf("Error: Failed to list all assets in the vault.\n");
        }
      }
      else
      {
        if (list_all_assets(filename, password) != 0)
        {
          printf("Error: Failed to list all assets in the vault.\n");
        }
      }

      printf("Press ENTER to continue...");
      getchar();

      break;
    }
    case 4: // Retrieve asset from vault
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
    case 7: // Clone vault
    {
      uint8_t original_tpdv[FILENAME_SIZE] = {0}, original_password[PASSWORD_SIZE] = {0}, confirm_original_password[PASSWORD_SIZE] = {0}, cloned_tpdv[FILENAME_SIZE] = {0}, cloned_password[PASSWORD_SIZE] = {0};

      printf("Enter the original vault filename: ");
      if (fgets((char *)original_tpdv, FILENAME_SIZE, stdin) == NULL)
      {
        printf("Error: Invalid input. Please enter a string.\n");
        break;
      }

      for (int i = 0; i < FILENAME_SIZE; i++)
      {
        if (original_tpdv[i] == '\n')
        {
          original_tpdv[i] = '\0';
          break;
        }
      }

      printf("Enter the original vault password: ");
      if (fgets((char *)original_password, PASSWORD_SIZE, stdin) == NULL)
      {
        printf("Error: Invalid input. Please enter a string.\n");
        break;
      }

      for (int i = 0; i < PASSWORD_SIZE; i++)
      {
        if (original_password[i] == '\n')
        {
          original_password[i] = '\0';
          break;
        }
      }

      printf("Confirm the original vault password: ");
      if (fgets((char *)confirm_original_password, PASSWORD_SIZE, stdin) == NULL)
      {
        printf("Error: Invalid input. Please enter a string.\n");
        break;
      }

      for (int i = 0; i < PASSWORD_SIZE; i++)
      {
        if (confirm_original_password[i] == '\n')
        {
          confirm_original_password[i] = '\0';
          break;
        }
      }

      if (memcmp(original_password, confirm_original_password, PASSWORD_SIZE) != 0)
      {
        printf("Error: The passwords do not match.\n");
        break;
      }

      printf("\033[H\033[J"); // Clear the screen

      printf("Enter the cloned vault filename: ");
      if (fgets((char *)cloned_tpdv, FILENAME_SIZE, stdin) == NULL)
      {
        printf("Error: Invalid input. Please enter a string.\n");
        break;
      }

      for (int i = 0; i < FILENAME_SIZE; i++)
      {
        if (cloned_tpdv[i] == '\n')
        {
          cloned_tpdv[i] = '\0';
          break;
        }
      }

      printf("Enter the cloned vault password: ");
      if (fgets((char *)cloned_password, PASSWORD_SIZE, stdin) == NULL)
      {
        printf("Error: Invalid input. Please enter a string.\n");
        break;
      }

      for (int i = 0; i < PASSWORD_SIZE; i++)
      {
        if (cloned_password[i] == '\n')
        {
          cloned_password[i] = '\0';
          break;
        }
      }

      printf("\033[H\033[J"); // Clear the screen

      if (clone_tpdv(original_tpdv, original_password, cloned_tpdv, cloned_password) != 0)
      {
        printf("Error: Failed to clone the vault.\n");
      }

      printf("Vault cloned successfully.\n\n");

      printf("Press ENTER to continue...");
      getchar();

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