/**
*   Copyright(C) 2011-2015 Intel Corporation All Rights Reserved.
*
*   The source code, information  and  material ("Material") contained herein is
*   owned  by Intel Corporation or its suppliers or licensors, and title to such
*   Material remains  with Intel Corporation  or its suppliers or licensors. The
*   Material  contains proprietary information  of  Intel or  its  suppliers and
*   licensors. The  Material is protected by worldwide copyright laws and treaty
*   provisions. No  part  of  the  Material  may  be  used,  copied, reproduced,
*   modified, published, uploaded, posted, transmitted, distributed or disclosed
*   in any way  without Intel's  prior  express written  permission. No  license
*   under  any patent, copyright  or  other intellectual property rights  in the
*   Material  is  granted  to  or  conferred  upon  you,  either  expressly,  by
*   implication, inducement,  estoppel or  otherwise.  Any  license  under  such
*   intellectual  property  rights must  be express  and  approved  by  Intel in
*   writing.
*
*   *Third Party trademarks are the property of their respective owners.
*
*   Unless otherwise  agreed  by Intel  in writing, you may not remove  or alter
*   this  notice or  any other notice embedded  in Materials by Intel or Intel's
*   suppliers or licensors in any way.
*/

#include "sgx_eid.h"
#include "error_codes.h"
#include "datatypes.h"
#include "sgx_urts.h"
#include "../App.h"
#include "UntrustedEnclaveMessageExchange.h"
#include "sgx_dh.h"
#include <errno.h>
#include <map>
#include <stdio.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include "GenericExecutionEnclave_u.h"

std::map<sgx_enclave_id_t, uint32_t>g_enclave_id_map;
std::map<sgx_enclave_id_t, int> enclave_id_to_tcp_session_map;

//Makes an sgx_ecall to the destination enclave to get session id and message1
ATTESTATION_STATUS session_request_ocall(sgx_enclave_id_t src_enclave_id, sgx_enclave_id_t dest_enclave_id, char* ipaddress, sgx_dh_msg1_t* dh_msg1, uint32_t* session_id)
{
    std::map<sgx_enclave_id_t, int>::iterator it = enclave_id_to_tcp_session_map.find(dest_enclave_id);
    int slave;

    // Check if the connection is already open
    if(it == enclave_id_to_tcp_session_map.end())
    {
            // There is no open connection.  Open a new one
            // GABE TODO malloc the thing?
        
        struct sockaddr_in slave_addr;
        memset(&slave_addr,0,sizeof(slave_addr));
        slave_addr.sin_family = AF_INET;
        slave_addr.sin_port = htons(4500); //4500 is the default port
        inet_aton(ipaddress, &slave_addr.sin_addr);           
 
        slave = socket(PF_INET,SOCK_STREAM,0);

        if (slave < 0) 
        {
            return INVALID_SESSION;
        }

        if (connect(slave,(const struct sockaddr *)&slave_addr,sizeof(slave_addr)) < 0) 
        {
            return INVALID_SESSION;
        }

        // Add to the map
        enclave_id_to_tcp_session_map[dest_enclave_id] =  slave;
    } 
    else 
    {
        slave = it->second;
    }

        
        
    // message is actually the sgx_dh_msg1 and the session id which is a uint32 
    char* rec_buffer[sizeof(sgx_dh_msg1_t) + 4];

    // We send our enclave id over to the other person //TODO GABE is this needed?
    send(slave, (char*) &src_enclave_id, sizeof(sgx_enclave_id_t), 0);

    // Listen for a response 
    recv(slave, rec_buffer, sizeof(sgx_dh_msg1_t) + 4, 0);

    // Parse out the msg1 response message and give it a session_id 
    memcpy(dh_msg1, &rec_buffer[0], sizeof(sgx_dh_msg1_t));
    memcpy(session_id, &rec_buffer[sizeof(sgx_dh_msg1_t)],4);


    return (ATTESTATION_STATUS) SGX_SUCCESS;
}

//Makes an sgx_ecall to the destination enclave sends message2 from the source enclave and gets message 3 from the destination enclave
ATTESTATION_STATUS exchange_report_ocall(sgx_enclave_id_t src_enclave_id, sgx_enclave_id_t dest_enclave_id, sgx_dh_msg2_t *dh_msg2, sgx_dh_msg3_t *dh_msg3, uint32_t session_id)
{

    std::map<sgx_enclave_id_t, int>::iterator it = enclave_id_to_tcp_session_map.find(dest_enclave_id);
    int slave;

    // Check if the connection is already open
    if(it == enclave_id_to_tcp_session_map.end())
    {
        // This shouldnt happen.  This means this has been called before the Session Request Ocall
        return INVALID_SESSION;
    }
    slave = it->second;
    // message is actually the sgx_dh_msg1 and the sesion 
    char* rec_buffer[sizeof(sgx_dh_msg1_t)];

    // Fire off Message 2 to the slave
    send(slave, dh_msg2, sizeof(sgx_dh_msg2_t), 0);


    // Get the response from the slave
    recv(slave, rec_buffer, sizeof(sgx_dh_msg3_t), 0);

    // Parse out msg 2 and return it to the enclave
    memcpy(dh_msg3, rec_buffer, sizeof(sgx_dh_msg3_t));


    return (ATTESTATION_STATUS) SGX_SUCCESS;
}

//Make an sgx_ecall to the destination enclave function that generates the actual response
ATTESTATION_STATUS send_request_ocall(sgx_enclave_id_t src_enclave_id, sgx_enclave_id_t dest_enclave_id, secure_message_t* req_message, 
                                size_t req_message_size, size_t max_payload_size, secure_message_t* resp_message, size_t resp_message_size)
{
    std::map<sgx_enclave_id_t, int>::iterator it = enclave_id_to_tcp_session_map.find(dest_enclave_id);
    int slave;

        // Check if the connection is already open
    if(it == enclave_id_to_tcp_session_map.end())
    {
        // This shouldnt happen.  This means this has been called before the Session Request Ocall
        return INVALID_SESSION;
    }
    slave = it->second;

    char* rec_buffer[1024];

    // // Fire off the request message to the slave
    send(slave, (void*)req_message, req_message_size, 0);

    // Get the response from the slave
    resp_message_size = recv(slave, rec_buffer, 1024, 0);

    // Parse out response and return it to the enclave
    memcpy(resp_message, rec_buffer, resp_message_size);

    return (ATTESTATION_STATUS) SGX_SUCCESS;
}

//Make an sgx_ecall to the destination enclave to close the session
ATTESTATION_STATUS end_session_ocall(sgx_enclave_id_t src_enclave_id, sgx_enclave_id_t dest_enclave_id)
{

    std::map<sgx_enclave_id_t, int>::iterator it = enclave_id_to_tcp_session_map.find(dest_enclave_id);
    int slave;

    // Check if the connection is already open
    if(it == enclave_id_to_tcp_session_map.end())
    {
        // This shouldnt happen.  This means this has been called before the Session Request Ocall
        return INVALID_SESSION;
    }
    slave = it->second;

    
    return (ATTESTATION_STATUS) SGX_SUCCESS;
}
