/*******************************************************************************
 *  (c) 2018 - 2024 Zondax AG
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 ********************************************************************************/
#pragma once

#include <zxmacros.h>

#include "parser_common.h"
#include "parser_txdef.h"
#include "zxtypes.h"

#ifdef __cplusplus
extern "C" {
#endif

#define TX_TYPE_TRANSFER 0
#define TX_TYPE_TRANSFER_CREATE 1
#define TX_TYPE_TRANSFER_CROSSCHAIN 2

#define JSON_NETWORK_ID "networkId"
#define JSON_META "meta"
#define JSON_SIGNERS "signers"
#define JSON_PUBKEY "pubKey"
#define JSON_CLIST "clist"
#define JSON_ARGS "args"
#define JSON_NAME "name"
#define JSON_CREATION_TIME "creationTime"
#define JSON_TTL "ttl"
#define JSON_CHAIN_ID "chainId"
#define JSON_GAS_LIMIT "gasLimit"
#define JSON_GAS_PRICE "gasPrice"
#define JSON_SENDER "sender"

#define TYPE_POS 0
#define RECIPIENT_POS 1
#define RECIPIENT_CHAIN_POS 2
#define NETWORK_POS 3
#define AMOUNT_POS 4
#define NAMESPACE_POS 5
#define MODULE_POS 6
#define GAS_PRICE_POS 7
#define GAS_LIMIT_POS 8
#define CREATION_TIME_POS 9
#define CHAIN_ID_POS 10
#define NONCE_POS 11
#define TTL_POS 12
#define PUBKEY_POS 13

typedef struct {
    const uint8_t *buffer;
    uint16_t bufferLen;
    uint16_t offset;
    union {
        tx_json_t *json;
        tx_hash_t *hash;
    };

} parser_context_t;

typedef struct {
    uint8_t len;
    char *data;
} chunk_t;

parser_error_t _read_json_tx(parser_context_t *c);
parser_error_t _read_hash_tx(parser_context_t *c);
tx_json_t *parser_getParserJsonObj();
tx_hash_t *parser_getParserHashObj();
chunk_t *parser_getChunks();
bool parser_usingChunks();
parser_error_t parser_findPubKeyInClist(uint16_t key_token_index);
parser_error_t parser_arrayElementToString(uint16_t json_token_index, uint16_t element_idx, const char **outVal,
                                           uint8_t *outValLen);
parser_error_t parser_validateMetaField();
parser_error_t parser_getTxName(uint16_t token_index);
parser_error_t parser_getValidClist(uint16_t *clist_token_index, uint16_t *num_args);
bool items_isNullField(uint16_t json_token_index);
parser_error_t parser_readChunks(parser_context_t *ctx);
parser_error_t parser_computeIncrementalHash(char *incrementalHash);

#ifdef __cplusplus
}
#endif