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


typedef struct {
    const uint8_t *buffer;
    uint16_t bufferLen;
    uint16_t offset;
    parser_tx_t *tx_obj;
} parser_context_t;

typedef struct {
    char key[20];
    char *buf;
    uint16_t len;
    parser_error_t (*toString)(char *inBuf, uint16_t inBufLen, char *outVal, uint16_t *outValLen);
} item_t;

typedef struct {
    item_t items[20];
    uint8_t numOfItems;
} item_array_t;

parser_error_t _read_json_tx(parser_context_t *c, parser_tx_t *v);
parser_error_t parser_initItems();
parser_error_t parser_storeItems(parser_context_t *ctx);
parser_error_t parser_getTotalItems(uint8_t *num_items);
parser_error_t parser_getJsonValueBuffer(parsed_json_t json_obj, const char *key_name, char **outVal, uint16_t *outValLen);
parser_error_t parser_initClistObject();
parser_error_t parser_initTransfer();
parser_error_t parser_getNthClistObject(parsed_json_t *json_obj, uint8_t clist_array_idx);
parser_error_t parser_isTransfer(parsed_json_t *json_obj);
parser_error_t parser_getTransferFrom(char **from, uint16_t *from_len);
parser_error_t parser_getTransferTo(char **to, uint16_t *to_len);
parser_error_t parser_getTransferAmount(char **amount, uint16_t *amount_len);
uint16_t parser_getNumberOfPossibleTransfers();
uint16_t parser_getNumberOfTransfers();
item_array_t *parser_getItemArray();

#ifdef __cplusplus
}
#endif