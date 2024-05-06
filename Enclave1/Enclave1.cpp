#include <stdarg.h>
#include <stdio.h> /* vsnprintf */

#include "sgx_trts.h"
#include "sgx_tseal.h"
#include "string.h"

#include "Enclave1.h"
#include "Enclave1_t.h" /* e1_print_string */

/*
 * printf:
 *   Invokes OCALL to display the enclave buffer to the terminal.
 */
int printf(const char *fmt, ...)
{
    char buf[BUFSIZ] = {'\0'};
    va_list ap;

    va_start(ap, fmt);
    (void)vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    ocall_e1_print_string(buf);
    return 0;
}

/*
 * ECALLs
 */

sgx_status_t seal(uint8_t *plaintext, uint32_t plaintext_len, sgx_sealed_data_t *sealed_data, uint32_t sealed_size)
{
    sgx_status_t status = sgx_seal_data(0, NULL, plaintext_len, plaintext, sealed_size, sealed_data);
    return status;
}

sgx_status_t unseal(sgx_sealed_data_t *sealed_data, uint32_t sealed_size, uint8_t *plaintext, uint32_t plaintext_len)
{
    sgx_status_t status = sgx_unseal_data(sealed_data, NULL, NULL, (uint8_t *)plaintext, &plaintext_len);
    return status;
}

uint32_t get_unsealed_data_size(uint8_t *sealed_data, uint32_t sealed_data_size)
{
    return sgx_get_encrypt_txt_len((const sgx_sealed_data_t *)sealed_data);
}

uint32_t get_sealed_data_size(uint32_t plaintext_len)
{
    return sgx_calc_sealed_data_size(0, plaintext_len);
}

void e1_check_password(const uint8_t *password, uint32_t password_size, const uint8_t *sealed_data, uint32_t sealed_size, int *result)
{
    uint32_t unsealed_size = sgx_get_encrypt_txt_len((const sgx_sealed_data_t *)sealed_data);
    uint8_t *unsealed_data = (uint8_t *)malloc(unsealed_size);
    if (unsealed_data == NULL)
    {
        printf("Failed to allocate memory for the unsealed data\n");
        return;
    }

    if (sgx_unseal_data((sgx_sealed_data_t *)sealed_data, NULL, NULL, unsealed_data, &unsealed_size) != SGX_SUCCESS)
    {
        printf("Failed to unseal the data\n");
        free(unsealed_data);
        return;
    }

    if (strcmp((char *)password, (char *)unsealed_data + FILENAME_SIZE) != 0)
    {
        printf("The password is incorrect.\n");
    }
    else
    {
        *result = 1;
    }

    free(unsealed_data);
}

void e1_add_asset(const uint8_t *asset_filename, uint32_t asset_filename_size, const uint8_t *sealed_data, uint32_t sealed_size, const uint8_t *asset, uint32_t asset_size, uint8_t *new_sealed_data, uint32_t new_sealed_size)
{
    uint32_t unsealed_size = sgx_get_encrypt_txt_len((const sgx_sealed_data_t *)sealed_data);

    uint8_t *unsealed_data = (uint8_t *)malloc(unsealed_size);
    if (unsealed_data == NULL)
    {
        printf("Failed to allocate memory for the unsealed data\n");
        return;
    }

    if (sgx_unseal_data((sgx_sealed_data_t *)sealed_data, NULL, NULL, unsealed_data, &unsealed_size) != SGX_SUCCESS)
    {
        printf("Failed to unseal the data\n");
        free(unsealed_data);
        return;
    }

    // Check how many assets are in the vault
    uint32_t number_of_assets = 0;
    memcpy(&number_of_assets, unsealed_data + FILENAME_SIZE + PASSWORD_SIZE + CREATOR_SIZE, ASSETS_SIZE);

    if (number_of_assets >= MAX_ASSETS)
    {
        printf("The vault is full\n");
        free(unsealed_data);
        return;
    }

    // Append the asset to the end of the vault
    uint32_t new_vault_size = unsealed_size + ASSETNAME_SIZE + 4 + asset_size;
    uint8_t *new_vault = (uint8_t *)malloc(new_vault_size);

    memcpy(new_vault, unsealed_data, unsealed_size);
    memcpy(new_vault + unsealed_size, asset_filename, ASSETNAME_SIZE);
    memcpy(new_vault + unsealed_size + ASSETNAME_SIZE, &asset_size, 4);
    memcpy(new_vault + unsealed_size + ASSETNAME_SIZE + 4, asset, asset_size);
    number_of_assets++;
    memcpy(new_vault + FILENAME_SIZE + PASSWORD_SIZE + CREATOR_SIZE, &number_of_assets, ASSETS_SIZE);

    // Hash all the assets
    sgx_sha256_hash_t hash_result;
    sgx_sha_state_handle_t sha_handle = NULL;
    if (sgx_sha256_init(&sha_handle) != SGX_SUCCESS)
    {
        printf("Failed to initialize the SHA256\n");
        free(unsealed_data);
        free(new_vault);
        return;
    }

    if (sgx_sha256_update(new_vault + HEADER_SIZE, new_vault_size - HEADER_SIZE, sha_handle) != SGX_SUCCESS)
    {
        printf("Failed to hash the assets\n");
        free(unsealed_data);
        free(new_vault);
        return;
    }

    if (sgx_sha256_get_hash(sha_handle, &hash_result) != SGX_SUCCESS)
    {
        printf("Failed to get the hash\n");
        free(unsealed_data);
        free(new_vault);
        return;
    }

    uint32_t nonce = 0;
    memcpy(&nonce, hash_result, NONCE_SIZE);
    memcpy(new_vault + HEADER_SIZE - NONCE_SIZE, &nonce, NONCE_SIZE);

    if (sgx_seal_data(0, NULL, new_vault_size, new_vault, new_sealed_size, (sgx_sealed_data_t *)new_sealed_data) != SGX_SUCCESS)
    {
        printf("Failed to seal the data\n");
    }

    free(unsealed_data);
    free(new_vault);
}

void e1_list_all_assets(const uint8_t *sealed_data, uint32_t sealed_size)
{
    uint32_t unsealed_size = sgx_get_encrypt_txt_len((const sgx_sealed_data_t *)sealed_data);

    uint8_t *unsealed_data = (uint8_t *)malloc(unsealed_size);
    if (unsealed_data == NULL)
    {
        printf("Failed to allocate memory for the unsealed data\n");
        return;
    }

    if (sgx_unseal_data((sgx_sealed_data_t *)sealed_data, NULL, NULL, unsealed_data, &unsealed_size) != SGX_SUCCESS)
    {
        printf("Failed to unseal the data\n");
        free(unsealed_data);
        return;
    }

    uint32_t number_of_assets = 0;
    memcpy(&number_of_assets, unsealed_data + HEADER_SIZE - NONCE_SIZE - ASSETS_SIZE, ASSETS_SIZE);
    if (number_of_assets == 0)
    {
        printf("The vault is empty\n");
        free(unsealed_data);
        return;
    }

    int offset = HEADER_SIZE; // Skip the header
    for (int index = 0; index < (int)number_of_assets; index++)
    {
        if (offset >= unsealed_size)
        {
            printf("End of the vault\n");
            break;
        }
        uint8_t asset_name[ASSETNAME_SIZE + 1] = {0}; // +1 for null terminator
        memcpy(asset_name, unsealed_data + offset, ASSETNAME_SIZE);
        asset_name[ASSETNAME_SIZE] = '\0'; // Null terminate the string

        uint32_t asset_size = 0;
        offset += ASSETNAME_SIZE;
        memcpy(&asset_size, unsealed_data + offset, 4);

        uint8_t asset_content[asset_size + 1]; // +1 for null terminator
        offset += 4;
        memcpy(asset_content, unsealed_data + offset, asset_size);
        asset_content[asset_size] = '\0'; // Null terminate the string

        offset += asset_size;

        printf("ASSET %d\n\n", index + 1);
        printf("Filename: %s\n", (char *)asset_name);
        printf("Content size: %u\n", asset_size);
        printf("Content: %s\n", (char *)asset_content);
        printf("\n\n");
    }
}

void e1_change_password(const uint8_t *old_password, uint32_t old_password_size, const uint8_t *new_password, uint32_t new_password_size, const uint8_t *sealed_data, uint32_t sealed_size, uint8_t *new_sealed_data, uint32_t new_sealed_size)
{
    uint32_t unsealed_size = sgx_get_encrypt_txt_len((const sgx_sealed_data_t *)sealed_data);
    uint8_t *unsealed_data = (uint8_t *)malloc(unsealed_size);
    if (unsealed_data == NULL)
    {
        printf("Failed to allocate memory for the unsealed data\n");
        return;
    }

    if (sgx_unseal_data((sgx_sealed_data_t *)sealed_data, NULL, NULL, unsealed_data, &unsealed_size) != SGX_SUCCESS)
    {
        printf("Failed to unseal the data\n");
        free(unsealed_data);
        return;
    }

    memcpy(unsealed_data + FILENAME_SIZE, new_password, new_password_size); // change the password

    if (sgx_seal_data(0, NULL, unsealed_size, unsealed_data, new_sealed_size, (sgx_sealed_data_t *)new_sealed_data) != SGX_SUCCESS)
    {
        printf("Failed to seal the data\n");
    }

    free(unsealed_data);
}

void e1_get_asset_hash_from_vault(const uint8_t *asset_filename, uint32_t asset_filename_size, const uint8_t *sealed_data, uint32_t sealed_size, uint8_t *hash, uint32_t hash_size)
{
    uint32_t unsealed_size = sgx_get_encrypt_txt_len((const sgx_sealed_data_t *)sealed_data);

    uint8_t *unsealed_data = (uint8_t *)malloc(unsealed_size);
    if (unsealed_data == NULL)
    {
        printf("Failed to allocate memory for the unsealed data\n");
        return;
    }

    if (sgx_unseal_data((sgx_sealed_data_t *)sealed_data, NULL, NULL, unsealed_data, &unsealed_size) != SGX_SUCCESS)
    {
        printf("Failed to unseal the data\n");
        free(unsealed_data);
        return;
    }

    // Search for the asset
    uint32_t number_of_assets = 0;
    memcpy(&number_of_assets, unsealed_data + FILENAME_SIZE + PASSWORD_SIZE + CREATOR_SIZE, ASSETS_SIZE);

    uint8_t asset_name[ASSETNAME_SIZE] = {0};
    uint32_t asset_size = 0;
    int offset = HEADER_SIZE;
    for (int index = 0; index < (int)number_of_assets; index++)
    {
        if (offset >= unsealed_size)
        {
            printf("Content out of bounds!\n");
            break;
        }

        memcpy(asset_name, unsealed_data + offset, ASSETNAME_SIZE);

        offset += ASSETNAME_SIZE;
        memcpy(&asset_size, unsealed_data + offset, 4);

        if (memcmp(asset_name, asset_filename, ASSETNAME_SIZE) == 0)
        {
            offset += 4; // skip the asset size
            break;
        }

        offset += sizeof(uint32_t) + asset_size;
    }

    // Get the asset content
    uint8_t *asset = (uint8_t *)malloc(asset_size);
    if (asset == NULL)
    {
        printf("Failed to allocate memory for the asset\n");
        free(unsealed_data);
        return;
    }

    memcpy(asset, unsealed_data + offset, asset_size);

    sgx_sha256_hash_t hash_result;
    sgx_sha_state_handle_t sha_handle = NULL;
    if (sgx_sha256_init(&sha_handle) != SGX_SUCCESS)
    {
        printf("Failed to initialize the SHA256\n");
        free(asset);
        free(unsealed_data);
        return;
    }

    if (sgx_sha256_update(asset, asset_size, sha_handle) != SGX_SUCCESS)
    {
        printf("Failed to hash the assets\n");
        free(asset);
        free(unsealed_data);
        return;
    }

    if (sgx_sha256_get_hash(sha_handle, &hash_result) != SGX_SUCCESS)
    {
        printf("Failed to get the hash\n");
        free(asset);
        free(unsealed_data);
        return;
    }

    memcpy(hash, hash_result, hash_size);

    free(asset);
    free(unsealed_data);
}