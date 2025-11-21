/*
 * Copyright (c) 2024, RISE Research Institutes of Sweden AB
 * All rights reserved.
 */

#ifndef PROJECT_CONF_H_
#define PROJECT_CONF_H_

/* EDHOC Client Configuration */
#define EDHOC_CONF_ROLE EDHOC_INITIATOR
#define EDHOC_CONF_METHOD EDHOC_METHOD0
#define EDHOC_CONF_TIMEOUT 100000
#define EDHOC_CONF_CID 0x37

/* CoAP configuration */
#define COAP_MAX_OPEN_TRANSACTIONS   8
#define COAP_MAX_OBSERVERS          8
#define COAP_MAX_CHUNK_SIZE         300

/* Network configuration */
#define UIP_CONF_MAX_ROUTES         30
#define RPL_CONF_MAX_PARENTS         8

/* EDHOC Authentication Configuration */
#define EDHOC_AUTH_KID 0x2b
#define EDHOC_CONF_AUTHENT_TYPE EDHOC_CRED_KID

/* EDHOC Cipher Suite Configuration */
#define EDHOC_CONF_SUPPORTED_SUITE_1 EDHOC_CIPHERSUITE_2
#define EDHOC_CONF_SUPPORTED_SUITE_2 EDHOC_CIPHERSUITE_6

/* EDHOC ECC Library Configuration */
#define EDHOC_CONF_ECC EDHOC_ECC_UECC

/* EDHOC Test Configuration */
#define EDHOC_CONF_TEST EDHOC_TEST_VECTOR_TRACE_DH

/* Logging levels */
#define LOG_CONF_LEVEL_EDHOC        LOG_LEVEL_INFO
#define LOG_CONF_LEVEL_COAP         LOG_LEVEL_WARN
#define LOG_CONF_WITH_COMPACT_BYTES 0

/* Server endpoint configuration */
#define EDHOC_CONF_SERVER_EP "coap://[fd00::202:2:2:2]"

#endif /* PROJECT_CONF_H_ */
