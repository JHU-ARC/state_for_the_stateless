#include "AppRPC.h"
#include <iostream>
#include <stdexcept>
#include <sstream>

const std::string base_cmd = "bitcoin-cli ";
const std::string base_cmd_tx_gen = "bitcoin-tx ";

const std::string space = " ";
const std::string base_empty_block = "02000000000000000000 ";
const std::string input_flag = "in=";
const std::string special_input_vout_index = ":0 ";
const std::string outaddr_flag = "outaddr=";
const std::string colon = ":";
const std::string outdata_flag = "outdata=";

const std::string sign_transaction_flag = "signrawtransaction ";
const std::string sign_complete_find_string = "\"complete\": true";

const std::string send_transaction_flag = "sendrawtransaction ";

const std::string mine_a_block = "bitcoin-cli -reget generate 1";

#ifdef USE_REGTEST
const std::string mode = "-regtest ";
#else
const std::string mode = "-testnet ";
#endif
 
constexpr char hexmap[] = {'0', '1', '2', '3', '4', '5', '6', '7',
                           '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

std::string hexStr(unsigned char *input_string, int len)
{
  std::string s(len * 2, ' ');
  for (int i = 0; i < len; ++i) {
    s[2 * i]     = hexmap[(input_string[i] & 0xF0) >> 4];
    s[2 * i + 1] = hexmap[input_string[i] & 0x0F];
  }
  return s;
}

void run_transaction_generation_test(std::string input_tx, double initial_tx_value)
{
    std::string opreturn_hexstring("24568753");
    std::string address("mji9XPbMGcuu6W9WWZoWxCcAbPZVKV5kUi");
    for( int i = 0; i< 10; i++)
    {
      input_tx = submit_transaction(input_tx, address, opreturn_hexstring, initial_tx_value - (.05*(i+1)), "0000");
      regtest_mine_a_block();
    }
}

void regtest_mine_a_block()
{
  exec(mine_a_block.c_str());
}

std::string get_hexed_block(std::string hashval)
{
    std::string rpc("getblock ");
    std::string verbose(" false");
    rpc = base_cmd + mode + rpc + hashval + verbose;
    const char* cmd = rpc.c_str();
    std::string pout = exec(cmd);
    if (pout.find("error") != std::string::npos)
        throw std::runtime_error(pout);
    std::stringstream ss(pout);
    std::string line;
    ss >> line;
    return line;
}

std::string submit_transaction(std::string input_tx, std::string target_address, std::string opreturn_hexstring, double amount, std::string public_output)
{

    std::string rpc_tx_gen("");

    rpc_tx_gen = base_cmd_tx_gen + mode + base_empty_block + input_flag + input_tx + special_input_vout_index
                     + outaddr_flag + std::to_string(amount) + colon  + target_address + space + outdata_flag + opreturn_hexstring
                     + space + outdata_flag + public_output;

    const char* cmd = rpc_tx_gen.c_str();
    std::string raw_tx = exec(cmd);

    //Sign the transaction
    std::string rpc_tx_sign("");
    rpc_tx_sign = base_cmd + mode + sign_transaction_flag + raw_tx;
    cmd = rpc_tx_sign.c_str();

    std::string signed_tx_output = exec(cmd);

    if(signed_tx_output.find(sign_complete_find_string) == std::string::npos)
      throw std::runtime_error(signed_tx_output);

    std::string signed_tx = signed_tx_output.substr(signed_tx_output.find("hex") +7, signed_tx_output.find("complete") - 18);

    std::string rpc_tx_send("");
    rpc_tx_send = base_cmd + mode + send_transaction_flag + signed_tx;
    cmd = rpc_tx_send.c_str();

    std::string tx_id = exec(cmd);

    // Strip out the newline char
    tx_id = tx_id.substr(0, tx_id.size()-1);

    std::cout << tx_id << std::endl;

    return tx_id;

}

double get_transaction_amount( std::string transaction_hash )
{
  std::string rpc("gettransaction ");
  rpc = base_cmd + mode + rpc + transaction_hash;
  const char* cmd = rpc.c_str();
  std::string pout = exec(cmd);

  size_t amount_begining = pout.find("amount");

  if (amount_begining == std::string::npos)
    throw std::runtime_error(pout);

  pout.erase(0, amount_begining + 9);
  size_t newline = pout.find("\n");
  pout.erase( newline-1, std::string::npos);
  return std::stod(pout.c_str());
}

int is_transaction_in_wallet( std::string transaction_hash) 
{
  if( transaction_hash.size() != 64 )
    return 0;

  for( int i = 0 ; i < transaction_hash.size(); i++)
  {
    if(!isxdigit(transaction_hash[i]))
      return 0;
  }
  std::string rpc("listunspent ");
  rpc = base_cmd + mode + rpc; 
  const char* cmd = rpc.c_str();
  std::string pout = exec(cmd);

  size_t transaction_index = pout.find(transaction_hash);

  return transaction_index != std::string::npos;
}

std::string get_block_hash(uint32_t index)
{
    std::string rpc("getblockhash ");
    rpc = base_cmd + mode + rpc + std::to_string(index);
    const char* cmd = rpc.c_str();
    std::string pout = exec(cmd);
    if (pout.find("error") != std::string::npos)
        throw std::runtime_error(pout);
    while (pout.find ("\n") != std::string::npos )
    {
        pout.erase (pout.find ("\n"), 1 );
    }
    return pout;
}

std::string get_new_address()
{
  std::string rpc("getnewaddress ");
  rpc = base_cmd + rpc;
  const char* cmd = rpc.c_str();
  std::string pout = exec(cmd);
  if (pout.find("error") != std::string::npos)
    throw std::runtime_error(pout);
  while (pout.find ("\n") != std::string::npos )
  {
    pout.erase (pout.find ("\n"), 1 );
  }
  return pout;
}

uint32_t get_num_confirmation_blocks( std::string transaction_hash )
{
  std::string rpc("gettransaction ");
  rpc = base_cmd + mode + rpc + transaction_hash;
  const char* cmd = rpc.c_str();
  std::string pout = exec(cmd);

  size_t confirmations_begining = pout.find("confirmations");

  if (confirmations_begining == std::string::npos)
    throw std::runtime_error(pout);

  pout.erase(0, confirmations_begining + 16);
  size_t newline = pout.find("\n");
  pout.erase( newline-1, std::string::npos);
  return std::stoi(pout.c_str());
}

std::string exec(const char* cmd)
{
    char buffer[128];
    std::string result = "";
    FILE* pipe = popen(cmd, "r");
    if (!pipe) throw std::runtime_error("popen() failed!");
    try {
        while (!feof(pipe)) {
            if (fgets(buffer, 128, pipe) != NULL){
                result += buffer;
            }
        }
    } catch (...) {
        pclose(pipe);
        throw;
    }
    pclose(pipe);
    return result;
}

uint32_t get_block_count()
{
  std::string rpc("getblockcount ");
  rpc = base_cmd + mode + rpc;
  const char* cmd = rpc.c_str();
  std::string pout = exec(cmd);
  if (pout.find("error") != std::string::npos)
    throw std::runtime_error(pout);
  return std::stoi(pout);
}
