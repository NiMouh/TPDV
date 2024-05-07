#include <stdarg.h>
#include <stdio.h> /* vsnprintf */

#include "sgx_trts.h"
#include "sgx_tseal.h"
#include "string.h"

#include "Enclave2.h"
#include "Enclave2_t.h" /* e1_print_string */

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
    ocall_e2_print_string(buf);
    return 0;
}

/*
 * ECALL (it just prints a string)
 */

/* SEAL/UNSEAL FUNCTIONS */

sgx_status_t e2_seal(uint8_t *plaintext, uint32_t plaintext_len, sgx_sealed_data_t *sealed_data, uint32_t sealed_size)
{
    sgx_status_t status = sgx_seal_data(0, NULL, plaintext_len, plaintext, sealed_size, sealed_data);
    return status;
}

sgx_status_t e2_unseal(sgx_sealed_data_t *sealed_data, uint32_t sealed_size, uint8_t *plaintext, uint32_t plaintext_len)
{
    sgx_status_t status = sgx_unseal_data(sealed_data, NULL, NULL, (uint8_t *)plaintext, &plaintext_len);
    return status;
}

uint32_t e2_get_unsealed_data_size(uint8_t *sealed_data, uint32_t sealed_data_size)
{
    return sgx_get_encrypt_txt_len((const sgx_sealed_data_t *)sealed_data);
}

uint32_t e2_get_sealed_data_size(uint32_t plaintext_len)
{
    return sgx_calc_sealed_data_size(0, plaintext_len);
}

/* FUNCTIONALITY FUNCTIONS */

void e2_list_all_assets(const uint8_t *sealed_data, uint32_t sealed_size)
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

void e2_check_password(const uint8_t *password, uint32_t password_size, const uint8_t *sealed_data, uint32_t sealed_size, int *result)
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

/* KEY EXCHANGE FUNCTIONS */

static sgx_dh_session_t e2_session;
static sgx_key_128bit_t e2_aek;
static sgx_dh_session_enclave_identity_t e2_initiator_identity;

// step 2
void e2_init_session(sgx_status_t *dh_status)
{
    *dh_status = sgx_dh_init_session(SGX_DH_SESSION_RESPONDER, &e2_session);
}

// step 3
void e2_create_message1(sgx_dh_msg1_t *msg1, sgx_status_t *dh_status)
{
    *dh_status = sgx_dh_responder_gen_msg1(msg1, &e2_session);
}

// step 7
void e2_process_message2(const sgx_dh_msg2_t *msg2, sgx_dh_msg3_t *msg3, sgx_status_t *dh_status)
{
    *dh_status = sgx_dh_responder_proc_msg2(msg2, msg3, &e2_session, &e2_aek, &e2_initiator_identity);
}

// show key
void e2_show_secret_key(void)
{
    printf("Enclave 2 AEK:");
    for (int i = 0; i < 16; i++)
        printf(" %02X", 0xFF & (int)e2_aek[i]);
    printf("\n");
}

void e2_decipher_and_seal(const uint8_t *ciphertext, uint32_t ciphertext_size, const uint8_t *password, uint32_t password_size, uint8_t *sealed_data, uint32_t sealed_size)
{
    uint8_t *plaintext = (uint8_t *)malloc(ciphertext_size);
    if (plaintext == NULL)
    {
        printf("Failed to allocate memory for the plaintext\n");
        return;
    }

    uint8_t p_ctr[16] = {0};

    uint32_t ctr_inc_bits = 128;

    // Decipher the ciphertext
    if (sgx_aes_ctr_decrypt(&e2_aek, ciphertext, ciphertext_size, p_ctr, ctr_inc_bits, plaintext) != SGX_SUCCESS)
    {
        printf("Failed to decipher the data\n");
        free(plaintext);
        return;
    }

    // Change the password
    memcpy(plaintext + FILENAME_SIZE, password, password_size);

    // Seal the plaintext
    if (sgx_seal_data(0, NULL, ciphertext_size, plaintext, sealed_size, (sgx_sealed_data_t *)sealed_data) != SGX_SUCCESS)
    {
        printf("Failed to seal the data\n");
        free(plaintext);
        return;
    }

    free(plaintext);
}