/*******************************************************************************
 *   (c) 2018 - 2024 Zondax AG
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

#include <stdio.h>
#include <zxformat.h>
#include <zxmacros.h>
#include <zxtypes.h>

#include "items.h"
#include "coin.h"
#include "crypto.h"
#include "crypto_helper.h"
#include "parser_impl.h"
#include "parser.h"

#define MAX_ITEM_LENGTH_IN_PAGE 40

parser_error_t parser_init_context(parser_context_t *ctx, const uint8_t *buffer, uint16_t bufferSize) {
    ctx->offset = 0;

    if (bufferSize == 0 || buffer == NULL) {
        // Not available, use defaults
        ctx->buffer = NULL;
        ctx->bufferLen = 0;
        return parser_init_context_empty;
    }

    ctx->buffer = buffer;
    ctx->bufferLen = bufferSize;
    return parser_ok;
}

parser_error_t parser_parse(parser_context_t *ctx, const uint8_t *data, size_t dataLen, tx_json_t *tx_obj) {
    CHECK_ERROR(parser_init_context(ctx, data, dataLen))
    ctx->tx_obj = tx_obj;

    CHECK_ERROR(_read_json_tx(ctx, tx_obj));

    items_initItems();
    items_storeItems(ctx);

    return parser_ok;
}

parser_error_t parser_validate(parser_context_t *ctx) {
    // Iterate through all items to check that all can be shown and are valid
    uint8_t numItems = 0;
    CHECK_ERROR(parser_getNumItems(ctx, &numItems))

    char tmpKey[MAX_ITEM_LENGTH_IN_PAGE] = {0};
    char tmpVal[MAX_ITEM_LENGTH_IN_PAGE] = {0};

    for (uint8_t idx = 0; idx < numItems; idx++) {
        uint8_t pageCount = 0;
        CHECK_ERROR(parser_getItem(ctx, idx, tmpKey, sizeof(tmpKey), tmpVal, sizeof(tmpVal), 0, &pageCount))
    }
    return parser_ok;
}

parser_error_t parser_getNumItems(const parser_context_t *ctx, uint8_t *num_items) {
    if (ctx->tx_obj == NULL) {
        return parser_tx_obj_empty;
    }

    *num_items = items_getTotalItems();

    return parser_ok;
}

static void cleanOutput(char *outKey, uint16_t outKeyLen, char *outVal, uint16_t outValLen) {
    MEMZERO(outKey, outKeyLen);
    MEMZERO(outVal, outValLen);
    snprintf(outKey, outKeyLen, "?");
    snprintf(outVal, outValLen, " ");
}

static parser_error_t checkSanity(uint8_t numItems, uint8_t displayIdx) {
    if (displayIdx >= numItems) {
        return parser_display_idx_out_of_range;
    }
    return parser_ok;
}

parser_error_t parser_getItem(const parser_context_t *ctx, uint8_t displayIdx, char *outKey, uint16_t outKeyLen,
                              char *outVal, uint16_t outValLen, uint8_t pageIdx, uint8_t *pageCount) {
    *pageCount = 1;
    uint8_t numItems = 0;
    item_array_t *item_array = items_getItemArray();
    char tempVal[255] = {0};
    uint16_t tempValLen = 0;
    CHECK_ERROR(parser_getNumItems(ctx, &numItems))
    CHECK_APP_CANARY()

    CHECK_ERROR(checkSanity(numItems, displayIdx))
    cleanOutput(outKey, outKeyLen, outVal, outValLen);

    snprintf(outKey, outKeyLen, "%s", item_array->items[displayIdx].key);
    ITEMS_TO_PARSER_ERROR(item_array->toString[displayIdx](item_array->items[displayIdx], tempVal, &tempValLen));
    pageString(outVal, outValLen, tempVal, pageIdx, pageCount);

    return parser_ok;
}
