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

typedef struct {
    char key[25];
    parsed_json_t json;
    parser_error_t (*toString)(parsed_json_t json_obj, char *outVal, uint16_t *outValLen);
} item_t;

typedef struct {
    item_t items[20];
    uint8_t numOfItems;
} item_array_t;

void items_initItems();
void items_storeItems();
uint16_t items_getTotalItems();
item_array_t *items_getItemArray();