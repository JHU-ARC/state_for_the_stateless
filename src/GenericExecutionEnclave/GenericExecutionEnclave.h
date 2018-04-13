#ifndef _GENERIC_EXECUTION_ENCLAVE_H_
#define _GENERIC_EXECUTION_ENCLAVE_H_

#include <stdlib.h>
#include <stdint.h>

#include "generic_execution_types.h"
#include "proof_types.h"

#if defined(__cplusplus)
extern "C" {
#endif

// Utility Functions

void check_initial_commitment(unsigned int counter, uint8_t* next_step_input, size_t next_step_input_size, uint8_t* program_code, size_t program_code_size, commitment_randomness_t* commitment_randomness, input_from_ledger_t* input_from_ledger, int* return_code);
void check_commitment(unsigned int counter, uint8_t* next_step_input, size_t next_step_input_size, state_ciphertext_t* previous_state, uint8_t* program_code, size_t program_code_size, commitment_randomness_t* commitment_randomness, input_from_ledger_t* input_from_ledger, int* return_code);
void decrypt_previous_state_and_verify_program_hash( state_ciphertext_t* ciphertext_previous_state, uint8_t* previous_transaction_hash, int counter, char* enclave_script, size_t enclave_script_size, public_output_t* public_output, uint8_t* plaintext_previous_state, int* return_code);
void next_step( char* enclave_script, size_t enclave_script_size, uint8_t* next_step_input, size_t next_step_input_size, uint8_t* plaintext_previous_state, uint8_t* plaintext_next_state, random_coins_t* random_coins, public_output_t* public_output, step_output_t* step_output, int* return_code);
void encrypt_next_state( char* enclave_script, size_t enclave_script_size, public_output_t* public_output, uint8_t* plaintext_next_state, uint8_t* current_transaction_hash, int counter, state_ciphertext_t* ciphertext_next_state, int* return_code);
void get_round_key( uint8_t* transaction_hash, state_ciphertext_key_t* round_key, int* return_code);
void generate_random_coins( uint8_t* transaction_hash, random_coins_t* random_coins, int* return_code);
void hex_encode_binary(uint8_t* in, size_t length, uint8_t* out);

#if defined(__cplusplus)
}
#endif

#endif /* !_ENCLAVE_H_ */
