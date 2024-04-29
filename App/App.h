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


#ifndef _APP_H_
#define _APP_H_

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>

#include "sgx_error.h"       /* sgx_status_t */
#include "sgx_eid.h"     /* sgx_enclave_id_t */

#define ENCLAVE1_FILENAME "enclave1.signed.so"

/* TPDV SIZES */
#define FILENAME_SIZE 50 // bytes
#define CREATOR_SIZE 50  // bytes
#define PASSWORD_SIZE 50 // bytes
#define HEADER_SIZE (FILENAME_SIZE + CREATOR_SIZE + PASSWORD_SIZE)
#define MAX_ASSETS 16000 // 16MB / 1KB = 16K assets

/* ASSET SIZES */
#define ASSETNAME_SIZE 46 // bytes
#define CONTENT_SIZE 950  // bytes

#define TPDV_SIZE (HEADER_SIZE + (ASSETNAME_SIZE + CONTENT_SIZE) * MAX_ASSETS)


#if defined(__cplusplus)
extern "C" {
#endif

/**
 * @brief Create a new vault
 *
 * @details It takes a nonce (random int number), filename, password, creator and number of assets (0 in this case), saves them in a unsigned char array, seals it and saves it in a file.
 *
 * @param filename Vault filename
 * @param filename_size Vault filename size
 * @param password Vault password
 * @param password_size Vault password size
 * @param creator Vault creator
 * @param creator_size Vault creator size
 *
 * @return 0 if the vault was created successfully, 1 otherwise
 */
int create_tpdv(uint8_t *filename, size_t filename_size, uint8_t *password, size_t password_size, uint8_t *creator, size_t creator_size);



#if defined(__cplusplus)
}
#endif

#endif /* !_APP_H_ */
