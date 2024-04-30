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
 * ECALL (it just prints a string)
 */

void e1_printf_hello_world(void)
{
  printf("Hello, %s!\n", "enclave");
}

int generate_random_number() {
    printf("Generating random number\n");
    return 42;
}

sgx_status_t seal(uint8_t* plaintext, uint32_t plaintext_len, sgx_sealed_data_t* sealed_data, uint32_t sealed_size) {
    sgx_status_t status = sgx_seal_data(0, NULL, plaintext_len, plaintext, sealed_size, sealed_data);
    return status;
}

sgx_status_t unseal(sgx_sealed_data_t* sealed_data, uint32_t sealed_size, uint8_t* plaintext, uint32_t plaintext_len) {
    sgx_status_t status = sgx_unseal_data(sealed_data, NULL, NULL, (uint8_t*)plaintext, &plaintext_len);
    return status;
}

uint32_t get_unsealed_data_size(uint8_t *sealed_data, uint32_t sealed_data_size) {
    return sgx_get_encrypt_txt_len((const sgx_sealed_data_t *)sealed_data);
}

uint32_t get_sealed_data_size(uint32_t plaintext_len) {
    return sgx_calc_sealed_data_size(0, plaintext_len);
}
