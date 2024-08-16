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

typedef struct {
    char key[25];
    uint16_t json_token_index;
    bool_t can_display;
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
