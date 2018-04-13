#include <stdio.h>

#include "GenericExecutionEnclave.h"
#include "GenericExecutionEnclave_t.h"
#include "BlockchainProofVerification.h"
#include "generic_execution_types.h"
#include "../Include/proof_types.h"

#include "sgx_trts.h"
#include "sgx_urts.h"
#include "sgx_tseal.h"
#include "sgx_tcrypto.h"

#include <string.h> //memcmp
#include <math.h>

#include "duktape.h"

sgx_aes_ctr_128bit_key_t* long_term_secret;

uint8_t debug_key[] = {0x22, 0x26, 0x67, 0x20, 0x99, 0x68, 0xfe, 0x27, 0x63, 0xed, 0xc7, 0x05, 0x2f, 0xbe, 0x25, 0x77};

const uint8_t round_key_prefix[] = {0x72, 0x6f, 0x75, 0x6e, 0x64, 0x5f, 0x6b, 0x65, 0x79};
const uint8_t random_coins_prefix[] = {0x72, 0x61, 0x6e, 0x64, 0x6f, 0x6d, 0x5f, 0x63, 0x6f, 0x69, 0x6e, 0x73};

const char hexmap[] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

void ecall_init( key_load_mode_t mode, sgx_sealed_data_t* sealed_key_in, sgx_sealed_data_t* sealed_key_out, int* return_code )
{
  if( long_term_secret == NULL)
  {
    long_term_secret = (sgx_aes_ctr_128bit_key_t*) malloc(sizeof(sgx_aes_ctr_128bit_key_t));
    if ( mode == GENERATE_NEW_KEY)
    {
      sgx_read_rand((uint8_t*) long_term_secret, LONG_TERM_KEY_LENGTH);

      uint32_t sealed_data_length = sgx_calc_sealed_data_size(0, LONG_TERM_KEY_LENGTH);

      sgx_status_t ret = sgx_seal_data(0, NULL, LONG_TERM_KEY_LENGTH, (uint8_t*) long_term_secret, sealed_data_length, sealed_key_out);
      if ( ret != SGX_SUCCESS) 
      {
        *return_code = RETURN_CODE_SEALING_FAILURE;
        return;
      }
    } 
    else if(mode == USE_DEBUG_KEY)
    {
      memcpy(long_term_secret, debug_key, LONG_TERM_KEY_LENGTH);
    }
    else {
      // load the key
      uint32_t length;
      sgx_status_t ret = sgx_unseal_data(sealed_key_in, NULL, NULL, (uint8_t*) long_term_secret, &length);
      if ( ret != SGX_SUCCESS) 
      {
        *return_code = RETURN_CODE_SEALING_FAILURE;
        return;
      }
    } 

    *return_code = RETURN_CODE_SUCCESS;
    return;
  }
  *return_code = RETURN_CODE_ALREADY_INITIALIZED;
  return;
}

void ecall_cleanup(int* return_code)
{
  if( long_term_secret == NULL)
  {
    *return_code = RETURN_CODE_UNINITIALIZED;
    return;
  }
  free(long_term_secret);
  *return_code = RETURN_CODE_SUCCESS;
  return;
}

void ecall_initial_step_blockchain(
                unsigned int counter, 
                uint8_t* next_step_input, size_t next_step_input_size,
                commitment_randomness_t* commitment_randomness,
                blockchain_proof_t* proof_struct,
                uint8_t* proof_buffer, size_t proof_buffer_size,
                input_from_ledger_t* input_from_ledger,
                char* javascript_program, size_t javascript_program_size,
                state_ciphertext_t* next_state,
                public_output_t* public_output,
                step_output_t* step_output,
                int* return_code)
{
  uint8_t plaintext_previous_state[STATE_CIPHERTEXT_BODY_LENGTH];
  uint8_t plaintext_next_state[STATE_CIPHERTEXT_BODY_LENGTH];

  uint8_t current_transaction_hash[SHA256_DIGEST_LENGTH];
  uint8_t previous_transaction_hash[SHA256_DIGEST_LENGTH];

  random_coins_t random_coins;
  public_output_t local_public_output;

  if( long_term_secret == NULL)
  {
    *return_code = RETURN_CODE_UNINITIALIZED;
    return;
  }

  memset(step_output, 0x00, STEP_OUTPUT_SIZE);
  memset(plaintext_previous_state, 0x00, STATE_CIPHERTEXT_BODY_LENGTH);
  memset(local_public_output, 0x00, MAX_PUBLIC_OUTPUT_LENGTH);

  populate_blockchain_proof_struct_from_buffer( proof_struct, proof_buffer, return_code);
  if( *return_code != RETURN_CODE_SUCCESS ) return;

  verify_blockchain_proof( input_from_ledger, proof_struct, current_transaction_hash, previous_transaction_hash, &local_public_output, return_code);
  if( *return_code != RETURN_CODE_SUCCESS ) return;

  if( counter != 0 )
  {
    *return_code = RETURN_CODE_COUNTER_MISMATCH; 
    return;
  }

  check_initial_commitment( counter, next_step_input, next_step_input_size, javascript_program, javascript_program_size, commitment_randomness, input_from_ledger, return_code);
  if( *return_code != RETURN_CODE_SUCCESS ) return;

  generate_random_coins(current_transaction_hash, &random_coins, return_code);
  if( *return_code != RETURN_CODE_SUCCESS ) return;

  next_step( javascript_program, javascript_program_size, next_step_input, next_step_input_size, plaintext_previous_state, plaintext_next_state, &random_coins, &local_public_output, step_output, return_code);
  if( *return_code != RETURN_CODE_SUCCESS ) return;

  encrypt_next_state( javascript_program, javascript_program_size, &local_public_output, plaintext_next_state, current_transaction_hash, counter, next_state, return_code);
  if( *return_code != RETURN_CODE_SUCCESS ) return;

  memcpy(public_output, local_public_output, MAX_PUBLIC_OUTPUT_LENGTH);

}

void ecall_next_step_blockchain(
                unsigned int counter,
                state_ciphertext_t* previous_state,
                uint8_t* next_step_input, size_t next_step_input_size,
                commitment_randomness_t* commitment_randomness,
                blockchain_proof_t* proof_struct, 
                uint8_t* proof_buffer, size_t proof_buffer_size,
                input_from_ledger_t* input_from_ledger,
                char* javascript_program, size_t javascript_program_size,
                state_ciphertext_t* next_state,
                public_output_t* public_output,
                step_output_t* step_output,
                int* return_code)
{
  uint8_t plaintext_previous_state[STATE_CIPHERTEXT_BODY_LENGTH];
  uint8_t plaintext_next_state[STATE_CIPHERTEXT_BODY_LENGTH];

  uint8_t current_transaction_hash[SHA256_DIGEST_LENGTH];
  uint8_t previous_transaction_hash[SHA256_DIGEST_LENGTH];

  random_coins_t random_coins;
  public_output_t local_public_output;

  if( long_term_secret == NULL)
  {
    *return_code = RETURN_CODE_UNINITIALIZED;
    return;
  }

  memset(step_output, 0x00, STEP_OUTPUT_SIZE);
  memset(local_public_output, 0x00, MAX_PUBLIC_OUTPUT_LENGTH);

  populate_blockchain_proof_struct_from_buffer( proof_struct, proof_buffer, return_code);
  if( *return_code != RETURN_CODE_SUCCESS ) return;

  verify_blockchain_proof( input_from_ledger, proof_struct, current_transaction_hash, previous_transaction_hash, &local_public_output, return_code);
  if( *return_code != RETURN_CODE_SUCCESS ) return;

  check_commitment( counter, next_step_input, next_step_input_size, previous_state, javascript_program, javascript_program_size, commitment_randomness, input_from_ledger, return_code);
  if( *return_code != RETURN_CODE_SUCCESS ) return;

  decrypt_previous_state_and_verify_program_hash( previous_state, previous_transaction_hash, counter, javascript_program, javascript_program_size, &local_public_output, plaintext_previous_state, return_code);
  if( *return_code != RETURN_CODE_SUCCESS ) return;

  generate_random_coins(current_transaction_hash, &random_coins, return_code);
  if( *return_code != RETURN_CODE_SUCCESS ) return;

  next_step( javascript_program, javascript_program_size, next_step_input, next_step_input_size, plaintext_previous_state, plaintext_next_state, &random_coins, &local_public_output, step_output, return_code); 
  if( *return_code != RETURN_CODE_SUCCESS ) return;

  encrypt_next_state( javascript_program, javascript_program_size, &local_public_output, plaintext_next_state,  current_transaction_hash, counter, next_state, return_code);
  if( *return_code != RETURN_CODE_SUCCESS ) return;

  memcpy(public_output, local_public_output, MAX_PUBLIC_OUTPUT_LENGTH);

}

// UTILITY FUNCTIONS
void check_initial_commitment(unsigned int counter, uint8_t* next_step_input, size_t next_step_input_size, uint8_t* program_code, size_t program_code_size, commitment_randomness_t* commitment_randomness, input_from_ledger_t* input_from_ledger, int* return_code)
{

  sgx_sha256_hash_t input_commitment;
  sgx_sha_state_handle_t sha_handle;

  sgx_status_t ret = sgx_sha256_init(&sha_handle);
  if (ret != SGX_SUCCESS)
  {
    *return_code = RETURN_CODE_ERROR_FROM_INTERNAL_LIBRARY;
    return;
  }

  ret = sgx_sha256_update((uint8_t*) &counter, sizeof(int), sha_handle);
  if (ret != SGX_SUCCESS)
  {
    *return_code = RETURN_CODE_ERROR_FROM_INTERNAL_LIBRARY;
    return;
  }

  ret = sgx_sha256_update(next_step_input, next_step_input_size, sha_handle);
  if (ret != SGX_SUCCESS)
  {
    *return_code = RETURN_CODE_ERROR_FROM_INTERNAL_LIBRARY;
    return;
  }

  ret = sgx_sha256_update(program_code, program_code_size, sha_handle);
  if (ret != SGX_SUCCESS)
  {
    *return_code = RETURN_CODE_ERROR_FROM_INTERNAL_LIBRARY;
    return;
  }

  ret = sgx_sha256_update((uint8_t*) commitment_randomness, COMMIT_RANDOMNESS_LENGTH, sha_handle);
  if (ret != SGX_SUCCESS)
  {
    *return_code = RETURN_CODE_ERROR_FROM_INTERNAL_LIBRARY;
    return;
  }

  ret = sgx_sha256_get_hash(sha_handle, &input_commitment);
  if (ret != SGX_SUCCESS)
  {
    *return_code = RETURN_CODE_ERROR_FROM_INTERNAL_LIBRARY;
    return;
  }

  ret = sgx_sha256_close(sha_handle);
  if (ret != SGX_SUCCESS)
  {
    *return_code = RETURN_CODE_ERROR_FROM_INTERNAL_LIBRARY;
    return;
  }

  if( memcmp(input_commitment, &(input_from_ledger->input_commitment), COMMIT_LENGTH) != 0 )
  {
    *return_code = RETURN_CODE_COMMITMENT_MISMATCH;
    return;
  }

  *return_code = RETURN_CODE_SUCCESS;
  return;

}

void check_commitment(unsigned int counter, uint8_t* next_step_input, size_t next_step_input_size, state_ciphertext_t* previous_state, uint8_t* program_code, size_t program_code_size, commitment_randomness_t* commitment_randomness, input_from_ledger_t* input_from_ledger, int* return_code)
{

  sgx_sha256_hash_t input_commitment;
  sgx_sha_state_handle_t sha_handle;

  sgx_status_t ret = sgx_sha256_init(&sha_handle);
  if (ret != SGX_SUCCESS)
  {
    *return_code = RETURN_CODE_ERROR_FROM_INTERNAL_LIBRARY;
    return;
  }

  ret = sgx_sha256_update((uint8_t*) &counter, sizeof(int), sha_handle);
  if (ret != SGX_SUCCESS)
  {
    *return_code = RETURN_CODE_ERROR_FROM_INTERNAL_LIBRARY;
    return;
  }

  ret = sgx_sha256_update(next_step_input, next_step_input_size, sha_handle);
  if (ret != SGX_SUCCESS)
  {
    *return_code = RETURN_CODE_ERROR_FROM_INTERNAL_LIBRARY;
    return;
  }

  ret = sgx_sha256_update((uint8_t*) previous_state, sizeof(state_ciphertext_t), sha_handle);
  if (ret != SGX_SUCCESS)
  {
    *return_code = RETURN_CODE_ERROR_FROM_INTERNAL_LIBRARY;
    return;
  }

  ret = sgx_sha256_update(program_code, program_code_size, sha_handle);
  if (ret != SGX_SUCCESS)
  {
    *return_code = RETURN_CODE_ERROR_FROM_INTERNAL_LIBRARY;
    return;
  }

  ret = sgx_sha256_update((uint8_t*) commitment_randomness, COMMIT_RANDOMNESS_LENGTH, sha_handle);
  if (ret != SGX_SUCCESS)
  {
    *return_code = RETURN_CODE_ERROR_FROM_INTERNAL_LIBRARY;
    return;
  }

  ret = sgx_sha256_get_hash(sha_handle, &input_commitment);
  if (ret != SGX_SUCCESS)
  {
    *return_code = RETURN_CODE_ERROR_FROM_INTERNAL_LIBRARY;
    return;
  }

  ret = sgx_sha256_close(sha_handle);
  if (ret != SGX_SUCCESS)
  {
    *return_code = RETURN_CODE_ERROR_FROM_INTERNAL_LIBRARY;
    return;
  }

  if( memcmp(input_commitment, &(input_from_ledger->input_commitment), COMMIT_LENGTH) != 0 )
  {
    *return_code = RETURN_CODE_COMMITMENT_MISMATCH;
    return;
  }

  *return_code = RETURN_CODE_SUCCESS;
  return;

}

void decrypt_previous_state_and_verify_program_hash( state_ciphertext_t* ciphertext_previous_state, uint8_t* previous_transaction_hash, int counter, char* enclave_script, size_t enclave_script_size, public_output_t* public_output, uint8_t* plaintext_previous_state, int* return_code)
{

  //actually decrypt
  state_ciphertext_key_t key;
  uint8_t plaintext_buffer[STATE_CIPHERTEXT_BODY_TOTAL_LENGTH];

  get_round_key(previous_transaction_hash, &key, return_code);
  if(*return_code != RETURN_CODE_SUCCESS) return;

  sgx_status_t ret = sgx_rijndael128GCM_decrypt(&key, (uint8_t*) &(ciphertext_previous_state->ciphertext), STATE_CIPHERTEXT_BODY_TOTAL_LENGTH, plaintext_buffer, (uint8_t*) &(ciphertext_previous_state->iv), STATE_CIPHERTEXT_IV_LENGTH, (uint8_t*) &(ciphertext_previous_state->aad), STATE_CIPHERTEXT_AAD_LENGTH, &(ciphertext_previous_state->tag)); 
  if (ret != SGX_SUCCESS)
  {
    *return_code = RETURN_CODE_STATE_DECRYPTION_FAILED;
    return;
  }

  state_ciphertext_body_t* parsed_plaintext = (state_ciphertext_body_t*) &(plaintext_buffer[0]);

  //verify the program hash
  sgx_sha256_hash_t program_hash; 
  ret = sgx_sha256_msg(enclave_script, enclave_script_size, &program_hash);
  if (ret != SGX_SUCCESS)
  {
    *return_code = RETURN_CODE_ERROR_FROM_INTERNAL_LIBRARY;
    return;
  }

  if( memcmp(&program_hash, parsed_plaintext->program_hash, STATE_CIPHERTEXT_PROGRAM_HASH_LENGTH) != 0 )
  {
    *return_code = RETURN_CODE_COMMITMENT_MISMATCH;
    return;
  }

  if( (counter-1) != parsed_plaintext->counter)
  {
    *return_code = RETURN_CODE_COUNTER_MISMATCH;
    return;
  } 

  //verify the public output hash 
  sgx_sha256_hash_t public_output_hash; 
  ret = sgx_sha256_msg((uint8_t*) public_output, MAX_PUBLIC_OUTPUT_LENGTH, &public_output_hash);
  if (ret != SGX_SUCCESS)
  {
    *return_code = RETURN_CODE_ERROR_FROM_INTERNAL_LIBRARY;
    return;
  }

  if( memcmp(&public_output_hash, parsed_plaintext->public_output_hash, STATE_CIPHERTEXT_PUBLIC_OUTPUT_HASH_LENGTH) != 0 )
  {
    *return_code = RETURN_CODE_WRONG_PUBLIC_OUTPUT;
    return;
  }

  //copy out just the state part of the plaintext - we are done with the hash
  memcpy(plaintext_previous_state, parsed_plaintext->state_string, STATE_CIPHERTEXT_BODY_LENGTH);

  *return_code = RETURN_CODE_SUCCESS;
  return;

}

void next_step( char* enclave_script, size_t enclave_script_size, uint8_t* next_step_input, size_t next_step_input_size, uint8_t* plaintext_previous_state, uint8_t* plaintext_next_state, random_coins_t* random_coins, public_output_t* public_output, step_output_t* step_output, int* return_code)
{

  duk_context *ctx = duk_create_heap_default();

  if( !ctx ) 
  {
    *return_code = RETURN_CODE_DUK_CTX_CREATE_FAILURE;    
    return;
  }

  // Check for null termination
  if( enclave_script[enclave_script_size-1] != 0x00 )
  {
    *return_code = RETURN_CODE_PARAMETER_SANITIZATION_FAILED_PROGRAM_CODE;
    return;
  }

  if( next_step_input[next_step_input_size-1] != 0x00 )
  {
    *return_code = RETURN_CODE_PARAMETER_SANITIZATION_FAILED_STEP_INPUT;
    return;
  }

  uint8_t hex_encoded_random_coins[2*RANDOM_COINS_LENGTH+1];
  hex_encode_binary(random_coins[0], RANDOM_COINS_LENGTH, hex_encoded_random_coins);
  hex_encoded_random_coins[2*RANDOM_COINS_LENGTH] = 0x00;

  duk_push_string(ctx, enclave_script);

  if( duk_peval(ctx) != 0)
  {
    *return_code = RETURN_CODE_DUK_EXECUTION_FAILURE;
    char* error_buff;
    duk_size_t sz;
    error_buff = duk_safe_to_lstring(ctx, -1, &sz); 
    return;
  }
  duk_pop(ctx);

  duk_push_global_object(ctx);
  duk_get_prop_string(ctx, -1, "nextStep");

  duk_push_string(ctx, plaintext_previous_state);
  duk_push_string(ctx, next_step_input);
  duk_push_string(ctx, hex_encoded_random_coins);
 
  if (duk_pcall(ctx, 3 /*nargs*/) != 0) {
    *return_code = RETURN_CODE_DUK_EXECUTION_FAILURE;
    return;
  }

  char* result_buff;
  char* step_output_deliniater;
  char* public_output_deliniater;
  duk_size_t sz;
  result_buff = duk_to_lstring(ctx, -1, &sz);

  step_output_deliniater = strchr(result_buff, '@');

  memset(plaintext_next_state, 0x00, STATE_CIPHERTEXT_BODY_LENGTH);
  // Public output only happens if there is a '@' in the return string
  if( step_output_deliniater != NULL )
  {
   
    public_output_deliniater = strchr(step_output_deliniater+1, '@');
    if (public_output_deliniater == NULL)
    {
      *return_code = RETURN_CODE_DUKTAPE_ILLEGAL_RETURN;
      return;
    }

    size_t state_string_length = step_output_deliniater - result_buff;
    size_t output_length = (public_output_deliniater - result_buff) - state_string_length;
    size_t public_output_length = sz - output_length - state_string_length;
    memcpy(plaintext_next_state, result_buff, state_string_length);
    memcpy(step_output, step_output_deliniater+1, output_length-1); //Omit the '@'
    memcpy(public_output, public_output_deliniater+1, public_output_length-1); //Omit the '@'
    plaintext_next_state[state_string_length] = 0x00; // Make sure we end on a zero byte
  }
  else 
  {
    memcpy(plaintext_next_state, result_buff, sz);
    plaintext_next_state[sz] = 0x00; //Make sure we end on a zero byte
  }
  duk_pop(ctx);  /* pop result/error */

  duk_destroy_heap(ctx);

  *return_code = RETURN_CODE_SUCCESS;
  return;
}

void encrypt_next_state(char* enclave_script, size_t enclave_script_size, public_output_t* public_output, uint8_t* plaintext_next_state, uint8_t* current_transaction_hash, int counter, state_ciphertext_t* ciphertext_next_state, int* return_code)
{
  state_ciphertext_key_t key;

  state_ciphertext_body_t ciphertext_body;

  sgx_sha256_hash_t program_hash;
  sgx_status_t ret = sgx_sha256_msg(enclave_script, enclave_script_size, &program_hash);
  if (ret != SGX_SUCCESS)
  {
    *return_code = RETURN_CODE_ERROR_FROM_INTERNAL_LIBRARY;
    return;
  }

  sgx_sha256_hash_t public_output_hash;
  ret = sgx_sha256_msg((uint8_t*) public_output, MAX_PUBLIC_OUTPUT_LENGTH, &public_output_hash);
  if (ret != SGX_SUCCESS)
  {
    *return_code = RETURN_CODE_ERROR_FROM_INTERNAL_LIBRARY;
    return;
  }

  memcpy(&(ciphertext_body.state_string[0]), plaintext_next_state, STATE_CIPHERTEXT_BODY_LENGTH);
  memcpy(&(ciphertext_body.program_hash[0]), &program_hash, STATE_CIPHERTEXT_PROGRAM_HASH_LENGTH);
  memcpy(&(ciphertext_body.public_output_hash[0]), &public_output_hash, STATE_CIPHERTEXT_PUBLIC_OUTPUT_HASH_LENGTH);

  ciphertext_body.counter = counter;

  get_round_key(&(current_transaction_hash[0]) , &key, return_code);
  if(*return_code != RETURN_CODE_SUCCESS) return;

  // We generate a random key each time, so we dont have to worry about reusing IVs
  memset((uint8_t*) &(ciphertext_next_state->iv), 0x00, STATE_CIPHERTEXT_IV_LENGTH);

  ret = sgx_rijndael128GCM_encrypt(&key, (uint8_t*) &ciphertext_body, STATE_CIPHERTEXT_BODY_TOTAL_LENGTH, (uint8_t*) &(ciphertext_next_state->ciphertext), (uint8_t*) &(ciphertext_next_state->iv), STATE_CIPHERTEXT_IV_LENGTH, (uint8_t*) &(ciphertext_next_state->aad), STATE_CIPHERTEXT_AAD_LENGTH, &(ciphertext_next_state->tag)); 
  if (ret != SGX_SUCCESS) 
  {
    *return_code = RETURN_CODE_STATE_ENCRYPTION_FAILED;
    return;
  } 
  *return_code = RETURN_CODE_SUCCESS;
  return;
}

void get_round_key( uint8_t* transaction_hash, state_ciphertext_key_t* round_key, int* return_code)
{
  sgx_cmac_state_handle_t cmac_handle;

  sgx_status_t ret = sgx_cmac128_init(long_term_secret, &cmac_handle);
  if (ret != SGX_SUCCESS)
  {
    *return_code = RETURN_CODE_KEY_GEN_FAILED;
    return;
  }

  ret = sgx_cmac128_update( round_key_prefix, ROUND_KEY_PREFIX_LENGTH, cmac_handle);
  if (ret != SGX_SUCCESS)
  {
    *return_code = RETURN_CODE_KEY_GEN_FAILED;
    return;
  }

  ret = sgx_cmac128_update(transaction_hash, SHA256_DIGEST_LENGTH, cmac_handle);
  if (ret != SGX_SUCCESS)
  {
    *return_code = RETURN_CODE_KEY_GEN_FAILED;
    return;
  }

  ret = sgx_cmac128_final(cmac_handle, round_key);
  if (ret != SGX_SUCCESS)
  {
    *return_code = RETURN_CODE_KEY_GEN_FAILED;
    return;
  }

  ret = sgx_cmac128_close(cmac_handle);
  if (ret != SGX_SUCCESS)
  {
    *return_code = RETURN_CODE_KEY_GEN_FAILED;
    return;
  }

  *return_code = RETURN_CODE_SUCCESS;
  return;
}

void generate_random_coins( uint8_t* transaction_hash, random_coins_t* random_coins, int* return_code)
{
  sgx_cmac_state_handle_t cmac_handle;

  sgx_status_t ret = sgx_cmac128_init(long_term_secret, &cmac_handle);
  if (ret != SGX_SUCCESS)
  {
    *return_code = RETURN_CODE_KEY_GEN_FAILED;
    return;
  }

  ret = sgx_cmac128_update( random_coins_prefix, RANDOM_COINS_PREFIX_LENGTH, cmac_handle);
  if (ret != SGX_SUCCESS)
  {
    *return_code = RETURN_CODE_KEY_GEN_FAILED;
    return;
  }

  ret = sgx_cmac128_update(transaction_hash, SHA256_DIGEST_LENGTH, cmac_handle);
  if (ret != SGX_SUCCESS)
  {
    *return_code = RETURN_CODE_KEY_GEN_FAILED;
    return;
  }

  ret = sgx_cmac128_final(cmac_handle, random_coins);
  if (ret != SGX_SUCCESS)
  {
    *return_code = RETURN_CODE_KEY_GEN_FAILED;
    return;
  }

  ret = sgx_cmac128_close(cmac_handle);
  if (ret != SGX_SUCCESS)
  {
    *return_code = RETURN_CODE_KEY_GEN_FAILED;
    return;
  }

  *return_code = RETURN_CODE_SUCCESS;
  return;
}

void hex_encode_binary(uint8_t* in, size_t length, uint8_t* out)
{
  for (int i = 0; i < length; ++i) {
    out[2 * i]     = hexmap[(in[i] & 0xF0) >> 4];
    out[2 * i + 1] = hexmap[in[i] & 0x0F];
  }
}
