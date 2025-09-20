/*
 * Copyright (C) 2011-2021 Intel Corporation. All rights reserved.
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


#include <stdio.h>
#include <map>

#include "sgx_eid.h"
#include "sgx_urts.h"

#include "EnclaveInitiator_u.h"
#include "EnclaveResponder_u.h"
#include "sgx_utils.h"

#define ENCLAVE_INITIATOR_NAME "libenclave_initiator.signed.so"
#define ENCLAVE_RESPONDER_NAME "libenclave_responder.signed.so"

sgx_enclave_id_t initiator_enclave_id = 0, responder_enclave_id = 0;

#include <x86intrin.h> // For __rdtsc()                                         
uint64_t start_cycles, stop_cycles;

int main(int argc, char* argv[])
{
    int update = 0;
    uint32_t ret_status;
    sgx_status_t status;
    sgx_launch_token_t token = {0};

    (void)argc;
    (void)argv;

    start_cycles = __rdtsc();
    // load initiator and responder enclaves
    if (SGX_SUCCESS != sgx_create_enclave(ENCLAVE_INITIATOR_NAME, SGX_DEBUG_FLAG, &token, &update, &initiator_enclave_id, NULL)
        || SGX_SUCCESS != sgx_create_enclave(ENCLAVE_RESPONDER_NAME, SGX_DEBUG_FLAG, &token, &update, &responder_enclave_id, NULL)) {
        printf("failed to load enclave.\n");
        goto destroy_enclave;
    }
    stop_cycles = __rdtsc();
    printf("init enclave %ld\n", stop_cycles-start_cycles); 
    printf("succeed to load enclaves.\n");
        
    start_cycles = __rdtsc();
    // create ECDH session using initiator enclave, it would create session with responder enclave
    status = test_create_session(initiator_enclave_id, &ret_status);
    if (status != SGX_SUCCESS || ret_status != 0) {
     	printf("failed to establish secure channel: ECALL return 0x%x, error code is 0x%x.\n", status, ret_status);
       	goto destroy_enclave;
    }
    stop_cycles = __rdtsc();
    printf("create session enclave %ld\n", stop_cycles-start_cycles); 
    printf("succeed to establish secure channel.\n");

    start_cycles = __rdtsc();
    // test message exchanging between initiator enclave and responder enclave
    status = test_message_exchange(initiator_enclave_id, &ret_status);
    if (status != SGX_SUCCESS || ret_status != 0) {
        printf("test_message_exchange Ecall failed: ECALL return 0x%x, error code is 0x%x.\n", status, ret_status);
        goto destroy_enclave;
    }
    stop_cycles = __rdtsc();
    printf("message enclave %ld\n", stop_cycles-start_cycles); 
    printf("Succeed to exchange secure message...\n");

    start_cycles = __rdtsc();
    // close ECDH session
    status = test_close_session(initiator_enclave_id, &ret_status);
    if (status != SGX_SUCCESS || ret_status != 0) {
        printf("test_close_session Ecall failed: ECALL return 0x%x, error code is 0x%x.\n", status, ret_status);
        goto destroy_enclave;
    }
    stop_cycles = __rdtsc();
    printf("close session enclave %ld\n", stop_cycles-start_cycles); 
    printf("Succeed to close Session...\n");

destroy_enclave:
    start_cycles = __rdtsc();
    sgx_destroy_enclave(initiator_enclave_id);
    sgx_destroy_enclave(responder_enclave_id);
    stop_cycles = __rdtsc();
    printf("destroy enclave %ld\n", stop_cycles-start_cycles);

    return 0;
}
 
