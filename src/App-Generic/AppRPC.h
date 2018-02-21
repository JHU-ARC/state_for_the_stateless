#ifndef _APP_RPC_H_
#define _APP_RPC_H_

#include <string>

std::string hexStr(unsigned char *input_string, int len);
void run_transaction_generation_test(std::string input_tx, double initial_tx_value);
void regtest_mine_a_block();
std::string get_hexed_block(std::string hashval);
std::string submit_transaction(std::string input_tx, std::string target_address, std::string opreturn_hexstring, double amount, std::string public_output);
double get_transaction_amount( std::string transaction_hash );
int is_transaction_in_wallet( std::string transaction_hash);
std::string get_block_hash(uint32_t index);
std::string get_new_address();
uint32_t get_num_confirmation_blocks( std::string transaction_hash );
std::string exec(const char* cmd);
uint32_t get_block_count();


#endif
