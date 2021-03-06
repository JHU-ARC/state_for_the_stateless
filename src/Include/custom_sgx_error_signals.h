#ifndef _CUSTOM_SGX_ERROR_SIGNALS_H_
#define _CUSTOM_SGX_ERROR_SIGNALS_H_

#define RETURN_CODE_SUCCESS 1

  // General return codes
#define RETURN_CODE_PARAMETER_SANITIZATION_FAILED 101
#define RETURN_CODE_OUT_OF_TIME 102
#define RETURN_CODE_SECRETS_NOT_SET 103
#define RETURN_CODE_ERROR_FROM_INTERNAL_LIBRARY 104
#define RETURN_CODE_OPERATIONS_OUT_OF_ORDER 105
#define RETURN_CODE_NOT_READY_TO_DECRYPT 106

  // Return Codes for CT
#define RETURN_CODE_STH_SIG_INVALID 201
#define RETURN_CODE_MERKLE_TREE_INVALID 202
#define RETURN_CODE_WRONG_DATA_IN_CERTIFICATE 203
  
  // Return codes for bitcoin
#define RETURN_CODE_BLOCK_VERIFICATION_FAILED 301
#define RETURN_CODE_WRONG_DATA_IN_BLOCK 302

#endif
