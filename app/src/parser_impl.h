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
#define JSON_SENDER         "sender"
#define JSON_CHAIN_ID       "chainId"
#define JSON_GAS_LIMIT      "gasLimit"
#define JSON_GAS_PRICE      "gasPrice"
#define JSON_SIGNERS        "signers"
#define JSON_CLIST          "clist"

typedef struct {
    const uint8_t *buffer;
    uint16_t bufferLen;
    uint16_t offset;
    parser_tx_t *tx_obj;
} parser_context_t;

parser_error_t _read_json_tx(parser_context_t *c, parser_tx_t *v);
parser_tx_t *parser_getParserTxObj();
parser_error_t parser_initClistObject();
parser_error_t parser_initTransfer();
parser_error_t parser_isTransfer(parsed_json_t *json_obj);
parser_error_t parser_getTransferFrom(char **from, uint16_t *from_len);
parser_error_t parser_getTransferTo(char **to, uint16_t *to_len);
parser_error_t parser_getTransferAmount(char **amount, uint16_t *amount_len);
uint16_t parser_getNumberOfClistElements();
uint16_t parser_getNumberOfTransfers();
parser_error_t parser_getJsonValue(parsed_json_t *json_obj, const char *key);
parser_error_t parser_getNthClistElement(parsed_json_t *json_obj, uint8_t clist_array_idx);
parser_error_t parser_getGasObject(parsed_json_t *json_obj);
parser_error_t parser_getChainId(parsed_json_t *json_obj);

#ifdef __cplusplus
}
#endif