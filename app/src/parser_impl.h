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

#define JSON_NETWORK_ID     "networkId"
#define JSON_META           "meta"
#define JSON_SIGNERS        "signers"
#define JSON_PUBKEY         "pubKey"
#define JSON_CLIST          "clist"
#define JSON_ARGS           "args"
#define JSON_NAME           "name"
#define JSON_CREATION_TIME  "creationTime"
#define JSON_TTL            "ttl"
#define JSON_CHAIN_ID       "chainId"
#define JSON_GAS_LIMIT      "gasLimit"
#define JSON_GAS_PRICE      "gasPrice"
#define JSON_SENDER         "sender"

typedef struct {
    const uint8_t *buffer;
    uint16_t bufferLen;
    uint16_t offset;
    tx_json_t *tx_obj;
} parser_context_t;

parser_error_t _read_json_tx(parser_context_t *c, tx_json_t *v);
tx_json_t *parser_getParserTxObj();
parser_error_t parser_findPubKeyInClist(uint16_t key_token_index);
parser_error_t parser_arrayElementToString(uint16_t json_token_index, uint16_t element_idx, char *outVal, uint8_t *outValLen);
parser_error_t parser_validateMetaField();
bool items_isNullField(uint16_t json_token_index);

#ifdef __cplusplus
}
#endif