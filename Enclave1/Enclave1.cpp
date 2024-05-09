#include <stdarg.h>
#include <stdio.h> /* vsnprintf */

#include "sgx_trts.h"
#include "sgx_tseal.h"
#include "string.h"

#include "Enclave1.h"
#include "Enclave1_t.h" /* e1_print_string */

/*
 * printf: Invokes OCALL to display the enclave buffer to the terminal.
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

/* SEAL/UNSEAL FUNCTIONS */

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

/* FUNCTIONALITY FUNCTIONS */

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

    if (strcmp((char *)password, (char *)unsealed_data + FILENAME_SIZE) == 0)
    {
        *result = 1;
    }

    free(unsealed_data);
}

void e1_check_nonce(const uint8_t *sealed_data, uint32_t sealed_size, int *result)
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

    sgx_sha256_hash_t hash_result;
    sgx_sha_state_handle_t sha_handle = NULL;
    if (sgx_sha256_init(&sha_handle) != SGX_SUCCESS)
    {
        printf("Failed to initialize the SHA256\n");
        free(unsealed_data);
        return;
    }

    if (sgx_sha256_update(unsealed_data + HEADER_SIZE, unsealed_size - HEADER_SIZE, sha_handle) != SGX_SUCCESS)
    {
        printf("Failed to hash the assets\n");
        free(unsealed_data);
        return;
    }

    if (sgx_sha256_get_hash(sha_handle, &hash_result) != SGX_SUCCESS)
    {
        printf("Failed to get the hash\n");
        free(unsealed_data);
        return;
    }

    uint32_t nonce = 0;
    memcpy(&nonce, hash_result, NONCE_SIZE);

    uint32_t stored_nonce = 0;
    memcpy(&stored_nonce, unsealed_data + HEADER_SIZE - NONCE_SIZE, NONCE_SIZE);

    if (nonce == stored_nonce)
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

void e1_get_asset_size(const uint8_t *asset_filename, uint32_t asset_filename_size, const uint8_t *sealed_data, uint32_t sealed_size, uint32_t *asset_size)
{
    uint32_t unsealed_size = sgx_get_encrypt_txt_len((const sgx_sealed_data_t *)sealed_data);

    uint8_t unsealed_data[unsealed_size] = {0};
    if (sgx_unseal_data((sgx_sealed_data_t *)sealed_data, NULL, NULL, unsealed_data, &unsealed_size) != SGX_SUCCESS)
    {
        printf("Failed to unseal the data\n");
        return;
    }

    uint32_t number_of_assets = 0;
    memcpy(&number_of_assets, unsealed_data + HEADER_SIZE - NONCE_SIZE - ASSETS_SIZE, ASSETS_SIZE);

    uint8_t asset_name[ASSETNAME_SIZE] = {0};
    uint32_t asset_content_size = 0;
    uint8_t *ptr = unsealed_data + HEADER_SIZE;
    for (int index = 0; index < number_of_assets; index++)
    {
        if (ptr >= unsealed_data + unsealed_size)
        {
            printf("Content out of bounds!\n");
            break;
        }

        memcpy(asset_name, ptr, ASSETNAME_SIZE);
        ptr += ASSETNAME_SIZE;

        memcpy(&asset_content_size, ptr, sizeof(uint32_t));
        ptr += sizeof(uint32_t);

        if (memcmp(asset_name, asset_filename, ASSETNAME_SIZE) == 0)
        {
            *asset_size = asset_content_size;
            return;
        }

        ptr += asset_content_size;
    }

    printf("The asset was not found\n");
}

void e1_retrieve_asset(const uint8_t *asset_filename, uint32_t asset_filename_size, const uint8_t *sealed_data, uint32_t sealed_size, uint8_t *asset, uint32_t asset_size)
{
    uint32_t unsealed_size = sgx_get_encrypt_txt_len((const sgx_sealed_data_t *)sealed_data);

    uint8_t unsealed_data[unsealed_size] = {0};
    if (sgx_unseal_data((sgx_sealed_data_t *)sealed_data, NULL, NULL, unsealed_data, &unsealed_size) != SGX_SUCCESS)
    {
        printf("Failed to unseal the data\n");
        return;
    }

    uint32_t number_of_assets = 0;
    memcpy(&number_of_assets, unsealed_data + HEADER_SIZE - NONCE_SIZE - ASSETS_SIZE, ASSETS_SIZE);

    uint8_t asset_name[ASSETNAME_SIZE] = {0};
    uint32_t asset_content_size = 0;
    uint8_t *ptr = unsealed_data + HEADER_SIZE;
    for (int index = 0; index < number_of_assets; index++)
    {
        if (ptr >= unsealed_data + unsealed_size)
        {
            printf("Content out of bounds!\n");
            break;
        }

        memcpy(asset_name, ptr, ASSETNAME_SIZE);
        ptr += ASSETNAME_SIZE;

        memcpy(&asset_content_size, ptr, sizeof(uint32_t));
        ptr += sizeof(uint32_t);

        if (memcmp(asset_name, asset_filename, ASSETNAME_SIZE) != 0)
        {
            ptr += asset_content_size;
            continue;
        }

        if (asset_size < asset_content_size)
        {
            printf("Provided buffer is too small for asset\n");
            return;
        }

        memcpy(asset, ptr, asset_content_size);
        return;
    }

    printf("Asset not found\n");
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

/* KEY EXCHANGE ECALLs */

static sgx_dh_session_t e1_session;
static sgx_key_128bit_t e1_aek; // Agreement Encryption Key
static sgx_dh_session_enclave_identity_t e1_responder_identity;

// step 1
void e1_init_session(sgx_status_t *dh_status)
{
    *dh_status = sgx_dh_init_session(SGX_DH_SESSION_INITIATOR, &e1_session);
}

// step 5
void e1_process_message1(const sgx_dh_msg1_t *msg1, sgx_dh_msg2_t *msg2, sgx_status_t *dh_status)
{
    *dh_status = sgx_dh_initiator_proc_msg1(msg1, msg2, &e1_session);
}

// step 9
void e1_process_message3(const sgx_dh_msg3_t *msg3, sgx_status_t *dh_status)
{
    *dh_status = sgx_dh_initiator_proc_msg3(msg3, &e1_session, &e1_aek, &e1_responder_identity);
}

// show key
void e1_show_secret_key(void)
{
    printf("Enclave 1 AEK:");
    for (int i = 0; i < 16; i++)
        printf(" %02X", 0xFF & (int)e1_aek[i]);
    printf("\n");
}

void e1_unseal_and_cipher(const uint8_t *sealed_data, uint32_t sealed_size, uint8_t *ciphertext, uint32_t ciphertext_size)
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

    uint8_t p_ctr[16] = {0};

    uint32_t ctr_inc_bits = 128;

    // Cipher with AES-CTR
    if (sgx_aes_ctr_encrypt(&e1_aek, unsealed_data, unsealed_size, p_ctr, ctr_inc_bits, ciphertext) != SGX_SUCCESS)
    {
        printf("Failed to cipher the data\n");
    }

    free(unsealed_data);
}