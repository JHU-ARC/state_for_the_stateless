#include "BlockchainProofVerification.h"

#include "proof_types.h"
#include "generic_execution_types.h"

#include "Bitcoin/block.h"
#include "Bitcoin/utilstrencodings.h"
#include "Bitcoin/streams.h"
#include "Bitcoin/merkleblock.h"
#include "Bitcoin/hash.h"
#include "Bitcoin/key.h"
#include "Bitcoin/base58.h"
#include "Bitcoin/transaction.h"
#include "Bitcoin/sign.h"
#include "Bitcoin/keystore.h"
#include "Bitcoin/chain.h"
#include "Bitcoin/pow.h"
#include "Bitcoin/sha1.h"

bool DecodeHexBlk(CBlock& block, const std::string& strHexBlk)
{
    if (!IsHex(strHexBlk))
        return false;
    std::vector<unsigned char> blockData(ParseHex(strHexBlk));
    CDataStream ssBlock(blockData, SER_NETWORK, PROTOCOL_VERSION);
    try {
        ssBlock >> block;
    }
    catch (const std::exception&) {
        return false;
    }
    return true;
}

bool verify_block_ignore_previous_block(CBlock block){
    CBlockHeader bh = block.GetBlockHeader();
    if (!CheckProofOfWork(block.GetHash(), block.nBits)){
        return false;
    }
    if(bh.nBits >= MINIMUM_BLOCK_DIFFICULTY){ 
      return true;
    }
    return false;
}

bool verify_block_wrt_previous_block(CBlock prevblock, CBlock block){
    CBlockHeader bh = block.GetBlockHeader();
    if (!CheckProofOfWork(block.GetHash(), block.nBits)){
        return false;
    }
    if(bh.nBits >= MINIMUM_BLOCK_DIFFICULTY && bh.hashPrevBlock == prevblock.GetHash()){ 
        return true;
    }
    return false;
}

void verify_blockchain_proof(input_from_ledger_t* input_from_ledger, blockchain_proof_t* proof, uint8_t* current_transaction_hash, uint8_t* previous_transaction_hash, public_output_t* public_output, int* return_code)
{

  CBlock cblock;
  CBlock cBlockOne;
  CBlock cBlockTwo;
  CBlock cBlockThree;
  CBlock cBlockFour;   
  CBlock cBlockFive;
  CBlock cBlockSix;  

  int block_zero_decode = DecodeHexBlk(cblock,        std::string(proof->block_zero, proof->block_zero + proof->block_zero_length));
  int block_one_decode  = DecodeHexBlk(cBlockOne,     std::string(proof->block_one, proof->block_one + proof->block_one_length));
  int block_two_decode  = DecodeHexBlk(cBlockTwo,     std::string(proof->block_two, proof->block_two + proof->block_two_length));
  int block_three_decode= DecodeHexBlk(cBlockThree,   std::string(proof->block_three, proof->block_three + proof->block_three_length));
  int block_four_decode = DecodeHexBlk(cBlockFour,    std::string(proof->block_four, proof->block_four + proof->block_four_length));
  int block_five_decode = DecodeHexBlk(cBlockFive,    std::string(proof->block_five, proof->block_five + proof->block_five_length));
  int block_six_decode  = DecodeHexBlk(cBlockSix,     std::string(proof->block_six, proof->block_six + proof->block_six_length));

  if (!(block_zero_decode && block_one_decode && block_three_decode && block_four_decode && block_five_decode && block_six_decode))
  {
    *return_code = RETURN_CODE_BLOCKCHAIN_BLOCK_DECODE_FAILURE;
    return;
  }

  int verify_zero = verify_block_ignore_previous_block(cblock);
  int verify_one = verify_block_wrt_previous_block(cblock, cBlockOne); 
  int verify_two = verify_block_wrt_previous_block(cBlockOne, cBlockTwo); 
  int verify_three = verify_block_wrt_previous_block(cBlockTwo, cBlockThree);
  int verify_four = verify_block_wrt_previous_block(cBlockThree, cBlockFour);
  int verify_five = verify_block_wrt_previous_block(cBlockFour, cBlockFive);
  int verify_six = verify_block_wrt_previous_block(cBlockFive, cBlockSix);

  if(!(verify_zero && verify_one && verify_two && verify_three && verify_four && verify_five && verify_six)) 
  {
    *return_code = RETURN_CODE_BLOCKCHAIN_BLOCKCHAIN_VERIFICATION_FAILURE;
    return;
  }

  std::string encoded_address(proof->target_address, proof->target_address + BITCOIN_ADDRESS_LENGTH);
  std::vector<unsigned char> decoded_address;
  DecodeBase58(encoded_address, decoded_address);

  uint8_t decoded_address_array[ DECODED_BITCOIN_ADDRESS_LENGTH ];
  for(int i =0; i < DECODED_BITCOIN_ADDRESS_LENGTH;i++) 
  {
    decoded_address_array[i] = decoded_address[i+1]; 
  }

  for(int i = 0; i< cblock.vtx.size(); i++)
  {
 
     CTransaction tx = cblock.vtx[i];

     txnouttype type;
     std::vector<CTxDestination> addresses;
     int nRequired;
     if (ExtractDestinations(tx.vout[0].scriptPubKey, type, addresses, nRequired))
     {
       if (memcmp(decoded_address_array, addresses.begin(), DECODED_BITCOIN_ADDRESS_LENGTH)!=0)
       {
         // Go to the next transacton in the block
         continue;
       }
     }

     CScript script;
     opcodetype opcode;
     script = tx.vout[1].scriptPubKey; //The OP_RETURN should always be the second transaction output
     std::vector<unsigned char> vch;
     CScript::const_iterator pc = script.begin();
     while (pc < script.end()) {
       if (!script.GetOp(pc, opcode, vch))  
       {
         break;
       }
       if (opcode == OP_RETURN)
       {
         // we compare to pc + 1 because we want to exclude the OP_RETURN intial byte
         if( memcmp( &*pc+1, &(input_from_ledger->input_commitment[0]), COMMIT_LENGTH) ==0)
         {

           if(tx.vout.size() < 3)
           {
             *return_code = RETURN_CODE_NO_PROPER_TRANSACTION_FOUND;
             return;
           }

           uint256 txhash = tx.GetHash();
           memcpy(current_transaction_hash, &(txhash), SHA256_DIGEST_LENGTH);

           uint256 prevtxhash = tx.vin[0].prevout.hash;
           memcpy(previous_transaction_hash, &(prevtxhash), SHA256_DIGEST_LENGTH);          

           CScript::const_iterator pc_public_output = tx.vout[2].scriptPubKey.begin();
           memcpy(public_output, &*pc_public_output+3, MAX_PUBLIC_OUTPUT_LENGTH);

           *return_code = RETURN_CODE_SUCCESS;
           return;
         }
       }
     }
  }
 
  *return_code = RETURN_CODE_NO_PROPER_TRANSACTION_FOUND;
  return;
}

void populate_blockchain_proof_struct_from_buffer( blockchain_proof_t* proof_struct, uint8_t* proof_buffer, int* return_code)
{
  proof_struct->block_zero  = &proof_buffer[0];
  proof_struct->block_one   = &proof_buffer[proof_struct->block_zero_length];
  proof_struct->block_two   = &proof_buffer[proof_struct->block_zero_length + proof_struct->block_one_length];
  proof_struct->block_three = &proof_buffer[proof_struct->block_zero_length + proof_struct->block_one_length + proof_struct->block_two_length];
  proof_struct->block_four  = &proof_buffer[proof_struct->block_zero_length + proof_struct->block_one_length + proof_struct->block_two_length + proof_struct->block_three_length];
  proof_struct->block_five  = &proof_buffer[proof_struct->block_zero_length + proof_struct->block_one_length + proof_struct->block_two_length + proof_struct->block_three_length + proof_struct->block_four_length];
  proof_struct->block_six   = &proof_buffer[proof_struct->block_zero_length + proof_struct->block_one_length + proof_struct->block_two_length + proof_struct->block_three_length + proof_struct->block_four_length + proof_struct->block_five_length];

  proof_struct->target_address =  &proof_buffer[proof_struct->block_zero_length + proof_struct->block_one_length + proof_struct->block_two_length + proof_struct->block_three_length + proof_struct->block_four_length + proof_struct->block_five_length + proof_struct->block_six_length];

  *return_code = RETURN_CODE_SUCCESS;
}
