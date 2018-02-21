#ifndef _BLOCKCHAIN_PROOF_VERIFICATION_H_
#define _BLOCKCHAIN_PROOF_VERIFICATION_H_

#include <stdlib.h>
#include <stdint.h>

#include "proof_types.h"
#include "generic_execution_types.h"

#if defined(__cplusplus)
extern "C" {
#endif

void populate_blockchain_proof_struct_from_buffer( blockchain_proof_t* proof_struct, uint8_t* proof_buffer, int* return_code);

void verify_blockchain_proof(input_from_ledger_t* target_string, blockchain_proof_t* proof, uint8_t* current_transaction_hash, uint8_t* previous_transaction_hash, public_output_t* public_output, int* return_code);

#if defined(__cplusplus)
}
#endif

#endif
