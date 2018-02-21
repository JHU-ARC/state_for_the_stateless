#include <iostream>
#include <sstream> 
#include <ctime>
#include <time.h>

#include "sgx_urts.h"
#include "sgx_status.h"
#include "AppRPC.h"
#include "AppSGX.h"
#include "App.h"

#include "../Include/generic_execution_types.h"

#include "GenericExecutionEnclave_u.h"

 
int getrandomcoins_devurandom(uint8_t* buffer , size_t num_bytes )
{
  FILE* f;

  f = fopen("/dev/urandom", "r");
  if (f == NULL)
  {
    printf("/dev/random could not be opened!");
    return 0;
  }
  fread(buffer, num_bytes, 1, f);
  fclose(f);
  return 1;
}

void print_help_message()
{
  printf("Usage: ./app-generic <Input Transaction Hash> [Optional: Tip Amount]\n");
}

int SGX_CDECL main(int argc, char *argv[]){

    sgx_status_t ret;
    int return_code;

    state_ciphertext_t previous_state;
    state_ciphertext_t next_state;

    input_from_ledger_t input_from_ledger;
    commitment_randomness_t commitment_randomness;
    blockchain_proof_t proof_struct; 

    step_output_t step_output;
    public_output_t public_output;
    memset(public_output, 0x00, MAX_PUBLIC_OUTPUT_LENGTH);

    std::string line_in;
    size_t next_step_input_size;
    uint8_t* proof_buffer;
    size_t proof_buffer_size;
    size_t program_code_size;
    unsigned int counter = 0;
    double tip = DEFAULT_TIP;


    int first_exec = 1;

    if(argc < 2) 
    {
      print_help_message();
      exit(0);
    }

    std::string input_tx(argv[1]);

    if(input_tx == "--help" || input_tx == "-h" || input_tx == "--h" || input_tx == "-help" || input_tx == "help" )
    {
      print_help_message();
      exit(0);
    }
     
    if(argc > 2)
    {
      tip = std::stod(argv[2]);
    }

    // check to make sure tx is actually in our wallet
    if(!is_transaction_in_wallet(input_tx))
    {
      printf("Transaction provided is not in the wallet\n");
      exit(0);
    }
 
    double tx_value = get_transaction_amount(input_tx) - tip; 

    FILE* f = fopen("script.js", "r");
    fseek(f, 0L, SEEK_END);
    program_code_size = ftell(f);
    rewind(f);

    char program_code[program_code_size+1];

    fread( &(program_code[0]), program_code_size, 1, f);

    program_code[program_code_size] = 0x00; //make sure it is null terminated

    /* Initialize the enclave */
    if(initialize_enclave() < 0){
        printf("Failed to Initialize Enclave!\n");
        return -1; 
    }

    while(1) {

      std::cout << "> Enter Input\n";
      std::cout << "> ";
      std::getline(std::cin, line_in);

      // make sure we have a null terminated string buffer
      next_step_input_size = line_in.size()+1; 
      uint8_t next_step_input[next_step_input_size]; 
      strcpy((char*) next_step_input, line_in.c_str());
      next_step_input[next_step_input_size-1] = 0x00;

      size_t starting_index = get_block_count()+1;
     
      int got_rand = getrandomcoins_devurandom(commitment_randomness, COMMIT_RANDOMNESS_LENGTH);
      if(!got_rand)
      {
        goto exit;
      }
   
      std::string address = get_new_address();

      uint8_t current_hash[COMMIT_LENGTH];
      SHA256_CTX sha256;
      SHA256_Init(&sha256);
      SHA256_Update(&sha256 , &counter , sizeof(int));
      SHA256_Update(&sha256, next_step_input, next_step_input_size);
      SHA256_Update(&sha256, commitment_randomness, COMMIT_RANDOMNESS_LENGTH);
      SHA256_Final(current_hash, &sha256);
      std::string next_block_hash = submit_transaction(input_tx, address, hexStr(current_hash, COMMIT_LENGTH), tx_value, hexStr(public_output, MAX_PUBLIC_OUTPUT_LENGTH));
      input_tx = next_block_hash;
      // decrease the amount we are sending the next time areound
      tx_value = tx_value - tip; // Tip Value

#ifndef USE_REGTEST
      while( get_num_confirmation_blocks(next_block_hash) < 7)
      {
        sleep(10);
      }
#else 
      for( int i = 0; i< 8; i++)
      {
        regtest_mine_a_block();
      }
#endif
      size_t current_buffer_offset = 0;

      std::string block_zero = get_hexed_block(get_block_hash(starting_index));
      size_t block_zero_length = block_zero.size();
      std::string block_one = get_hexed_block(get_block_hash(starting_index+1));
      size_t block_one_length = block_one.size();
      std::string block_two = get_hexed_block(get_block_hash(starting_index+2));
      size_t block_two_length = block_two.size();
      std::string block_three = get_hexed_block(get_block_hash(starting_index+3));
      size_t block_three_length = block_three.size();
      std::string block_four = get_hexed_block(get_block_hash(starting_index+4));
      size_t block_four_length = block_four.size();
      std::string block_five = get_hexed_block(get_block_hash(starting_index+5));
      size_t block_five_length = block_five.size();
      std::string block_six = get_hexed_block(get_block_hash(starting_index+6));
      size_t block_six_length = block_six.size();

      proof_buffer_size = block_zero_length + block_one_length + block_two_length + block_three_length + block_four_length + block_five_length + block_six_length + BITCOIN_ADDRESS_LENGTH;

      proof_buffer = (uint8_t*) malloc( (block_zero_length + block_one_length + block_two_length + block_three_length + block_four_length + block_five_length + block_six_length + BITCOIN_ADDRESS_LENGTH) * sizeof(uint8_t));
      if( proof_buffer == NULL )
      {
        printf("Failed to malloc space for proof buffer\n");
        goto exit;
      } 

      memcpy(&(proof_buffer[current_buffer_offset]), block_zero.c_str(), block_zero_length);
      current_buffer_offset += block_zero_length;
      memcpy(&(proof_buffer[current_buffer_offset]), block_one.c_str(), block_one_length);
      current_buffer_offset += block_one_length;
      memcpy(&(proof_buffer[current_buffer_offset]), block_two.c_str(), block_two_length);
      current_buffer_offset += block_two_length;
      memcpy(&(proof_buffer[current_buffer_offset]), block_three.c_str(), block_three_length);
      current_buffer_offset += block_three_length;
      memcpy(&(proof_buffer[current_buffer_offset]), block_four.c_str(), block_four_length);
      current_buffer_offset += block_four_length;
      memcpy(&(proof_buffer[current_buffer_offset]), block_five.c_str(), block_five_length);
      current_buffer_offset += block_five_length;
      memcpy(&(proof_buffer[current_buffer_offset]), block_six.c_str(), block_six_length);
      current_buffer_offset += block_six_length;
      memcpy(&(proof_buffer[current_buffer_offset]), address.c_str(), BITCOIN_ADDRESS_LENGTH); 

      proof_struct.block_zero_length = block_zero_length;
      proof_struct.block_one_length = block_one_length;
      proof_struct.block_two_length = block_two_length;
      proof_struct.block_three_length = block_three_length;
      proof_struct.block_four_length = block_four_length;
      proof_struct.block_five_length = block_five_length;
      proof_struct.block_six_length = block_six_length;

      memcpy(&(input_from_ledger.input_commitment), current_hash, COMMIT_LENGTH);

      memset( public_output, 0x00, MAX_PUBLIC_OUTPUT_LENGTH);

      if( first_exec ) 
      {

        sgx_sealed_data_t key_in[SEALED_DATA_LENGTH];
        sgx_sealed_data_t key_out[SEALED_DATA_LENGTH];

        ret = GenericExecutionEnclave_ecall_init( global_eid, GENERATE_NEW_KEY, key_in, key_out, &return_code);
        if( return_code != RETURN_CODE_SUCCESS )
        {
          goto handle_errors;
        }
        if (ret != SGX_SUCCESS) 
        {
            print_error_message(ret);
            goto exit;
        }

        ret = GenericExecutionEnclave_ecall_initial_step_blockchain( global_eid, counter, next_step_input, next_step_input_size, &commitment_randomness, &proof_struct, proof_buffer, proof_buffer_size, &input_from_ledger, program_code, program_code_size +1, &next_state, &public_output, &step_output, &return_code);
        if( return_code != RETURN_CODE_SUCCESS )
        {
          goto handle_errors;
        }
        if (ret != SGX_SUCCESS)
        {
            print_error_message(ret);
            goto exit;
        }

        first_exec = 0;
      }
      else {

        ret = GenericExecutionEnclave_ecall_next_step_blockchain( global_eid, counter, &previous_state, next_step_input, next_step_input_size, &commitment_randomness, &proof_struct, proof_buffer, proof_buffer_size, &input_from_ledger, program_code, program_code_size+1, &next_state, &public_output, &step_output, &return_code);
        if( return_code != RETURN_CODE_SUCCESS )
        {
          goto handle_errors;
        }
        if (ret != SGX_SUCCESS)
        {
            print_error_message(ret);
            goto exit;
        }

      }

      memcpy(&previous_state, &next_state, sizeof(state_ciphertext_t));
      memset(&next_state, 0x00, sizeof(state_ciphertext_t));
      counter++;
      printf("Step Output: %s\n", step_output);
      free(proof_buffer);
  } // End While

handle_errors:
  if(return_code == RETURN_CODE_COMMITMENT_MISMATCH)
  {
    printf("Error: RETURN_CODE_COMMITMENT_MISMATCH\n");
    printf("Input commitment doesnt match the commitment on the blockchain!\n");
    goto exit;
  }
  if(return_code == RETURN_CODE_PROGRAM_HASH_MISMATCH)
  {
    printf("Error: RETURN_CODE_PROGRAM_HASH_MISMATCH\n");
    printf("Program Doesnt Match previous state\n");
    goto exit;
  }
  if(return_code == RETURN_CODE_STATE_DECRYPTION_FAILED)
  {
    printf("Error: RETURN_CODE_STATE_DECRYPTION_FAILED\n");
    printf("Failed to decrypt old state.  Ciphertext has been tampered with or wrong key was derived\n");
    goto exit;
  }
  if(return_code == RETURN_CODE_STATE_ENCRYPTION_FAILED)
  {
    printf("Error: RETURN_CODE_STATE_ENCRYPTION_FAILED\n");
    printf("Failed to encrypt new state\n");
    goto exit;
  }
  if(return_code == RETURN_CODE_KEY_GEN_FAILED)
  {
    printf("Error: RETURN_CODE_KEY_GEN_FAILED\n");
    printf("Failed to derive new key.  Likely an SGX error\n");
    goto exit;
  }
  if(return_code == RETURN_CODE_SEALING_FAILURE)
  {
    printf("Error: RETURN_CODE_SEALING_FAILURE\n");
    printf("Failed to seal the long term secret.  Likely and SGX error\n");
    goto exit;
  }
  if(return_code == RETURN_CODE_ALREADY_INITIALIZED)
  {
    printf("Error: RETURN_CODE_ALREADY_INITIALIZED\n");
    printf("Attempted to load or generate a key when this enclave has already been initialized\n");
    goto exit;
  }
  if(return_code == RETURN_CODE_UNINITIALIZED)
  {
    printf("Error: RETURN_CODE_UNINITIALIZED\n");
    printf("Must load or generate key first!\n");
    goto exit;
  }
  if(return_code == RETURN_CODE_PARAMETER_SANITIZATION_FAILED_PROGRAM_CODE)
  {
    printf("Error: RETURN_CODE_PARAMETER_SANITIZATION_FAILED_PROGRAM_CODE\n");
    printf("Program code doesnt end with a null byte.\n");
    goto exit;
  }
  if(return_code == RETURN_CODE_PARAMETER_SANITIZATION_FAILED_STEP_INPUT)
  {
    printf("Error: RETURN_CODE_PARAMETER_SANITIZATION_FAILED_STEP_INPUT\n");
    printf("Step input doesnt end with an null byte.\n");
    goto exit;
  }
  if(return_code == RETURN_CODE_ERROR_FROM_INTERNAL_LIBRARY)
  {
    printf("Error: RETURN_CODE_ERROR_FROM_INTERNAL_LIBRARY\n");
    printf("SGX or Openssl has thrown an error.\n");
    goto exit;
  }
  if(return_code == RETURN_CODE_DUKTAPE_ILLEGAL_RETURN)
  {
    printf("Error: RETURN_CODE_DUKTAPE_ILLEGAL_RETURN\n");
    printf("Javascript return is not properly formatted\n");
    printf("State, Ouput, and Public output are seperated by '@'\n");
    printf("'@' can be ommited if there is only state.\n");
    goto exit;
  }
  if(return_code == RETURN_CODE_BLOCKCHAIN_BLOCK_DECODE_FAILURE)
  {
    printf("Error: RETURN_CODE_BLOCKCHAIN_BLOCK_DECODE_FAILURE\n");
    printf("Bitcoin Core Failed to decode the input block.  Check inputs.\n");
    goto exit;
  }
  if(return_code == RETURN_CODE_BLOCKCHAIN_BLOCKCHAIN_VERIFICATION_FAILURE)
  {
    printf("Error: RETURN_CODE_BLOCKCHAIN_BLOCKCHAIN_VERIFICATION_FAILURE\n");
    printf("Blocks did not verify!\n");
    goto exit;
  }
  if(return_code == RETURN_CODE_NO_PROPER_TRANSACTION_FOUND)
  {
    printf("Error: RETURN_CODE_NO_PROPER_TRANSACTION_FOUND\n");
    printf("No properly formatted transaction was found in this block!\n");
    printf("Either no block with the specified addes was found or it had too few outputs\n");
    goto exit;
  }
  if(return_code == RETURN_CODE_COUNTER_MISMATCH)
  {
    printf("Error: RETURN_CODE_COUNTER_MISMATCH\n");
    printf("Running on the wrong step counter!\n");
    goto exit;
  }
  if(return_code == RETURN_CODE_WRONG_PUBLIC_OUTPUT)
  {
    printf("Error: RETURN_CODE_WRONG_PUBLIC_OUTPUT\n");
    printf("Public output on blockchain doesnt match the recorded public output hash\n");
    goto exit;
  }
  if(return_code == RETURN_CODE_DUK_CTX_CREATE_FAILURE)
  {
    printf("Error: RETURN_CODE_DUK_CTX_CREATE_FAILURE\n");
    printf("Duktape failed to create a context!  Something is really wrong...\n");
    goto exit;
  }
  if(return_code == RETURN_CODE_DUK_EXECUTION_FAILURE)
  {
    printf("Error: RETURN_CODE_DUK_EXECUTION_FAILURE\n");
    printf("Duktape failed to execute.  Maybe your function isn't properly formatted or uses an illegal function call\n");
    goto exit;
  }

  printf("ERROR CODE: %d\n", return_code); 
exit:
    sgx_destroy_enclave(global_eid);
    return 0;
}
