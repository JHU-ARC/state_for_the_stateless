#ifndef _PROOF_TYPES_H_
#define _PROOF_TYPES_H_

#define BITCOIN_ADDRESS_LENGTH 34 
#define DECODED_BITCOIN_ADDRESS_LENGTH 20

typedef struct blockchain_proof_t {
  unsigned int block_zero_length;
  uint8_t* block_zero;
  unsigned int block_one_length;
  uint8_t* block_one;
  unsigned int block_two_length;
  uint8_t* block_two;
  unsigned int block_three_length;
  uint8_t* block_three;
  unsigned int block_four_length;
  uint8_t* block_four;
  unsigned int block_five_length;
  uint8_t* block_five;
  unsigned int block_six_length;
  uint8_t* block_six;
  uint8_t* target_address;
} blockchain_proof_t;

#endif
