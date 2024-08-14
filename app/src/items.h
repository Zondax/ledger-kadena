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
#include "zxtypes.h"
#include "parser_common.h"
#include "json_parser.h"

#define WARNING_TEXT "UNSAFE TRANSACTION. This transaction's code was not recognized and does not limit capabilities for all signers. Signing this transaction may make arbitrary actions on the chain including loss of all funds."
#define CAUTION_TEXT "'meta' field of transaction not recognized"
#define TX_TOO_LARGE_TEXT "Transaction too large for Ledger to display.  PROCEED WITH GREAT CAUTION.  Do you want to continue?"

typedef struct {
    char key[25];
    uint16_t json_token_index;
    bool can_display;
} item_t;

typedef enum {
    items_ok,
    items_error,
} items_error_t;

typedef struct {
    item_t items[20];
    uint8_t numOfItems;
    items_error_t (*toString[20])(item_t item, char *outVal, uint16_t *outValLen);
} item_array_t;

void items_initItems();
void items_storeItems();
uint16_t items_getTotalItems();
item_array_t *items_getItemArray();