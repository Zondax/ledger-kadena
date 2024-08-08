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

#include "parser.h"

#include <stdio.h>
#include <zxformat.h>
#include <zxmacros.h>
#include <zxtypes.h>
#include <base64.h>

#include "coin.h"
#include "crypto.h"
#include "crypto_helper.h"
#include "parser_impl.h"

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

parser_error_t parser_parse(parser_context_t *ctx, const uint8_t *data, size_t dataLen, parser_tx_t *tx_obj) {
    CHECK_ERROR(parser_init_context(ctx, data, dataLen))
    ctx->tx_obj = tx_obj;

    CHECK_ERROR(_read_json_tx(ctx, tx_obj));

    return parser_ok;
}

parser_error_t parser_validate(parser_context_t *ctx) {

    // TODO: validate the tx (JSON validation)

    // Iterate through all items to check that all can be shown and are valid
    uint8_t numItems = 0;
    CHECK_ERROR(parser_getNumItems(ctx, &numItems))

    char tmpKey[40] = {0};
    char tmpVal[40] = {0};

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

    *num_items = 10;

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
    CHECK_ERROR(parser_getNumItems(ctx, &numItems))
    CHECK_APP_CANARY()

    CHECK_ERROR(checkSanity(numItems, displayIdx))
    cleanOutput(outKey, outKeyLen, outVal, outValLen);

    switch (displayIdx) {
        case 0:
            snprintf(outKey, outKeyLen, "Signing");
            snprintf(outVal, outValLen, "Transaction");
            return parser_ok;
        case 1:
            snprintf(outKey, outKeyLen, "On Network");
            char net[9];
            uint16_t net_size;
            CHECK_ERROR(parser_getJsonValueAsString("networkId", net, &net_size));
            snprintf(outVal, net_size + 1, "%s", net);
            return parser_ok;
        case 2:
            snprintf(outKey, outKeyLen, "Requiring");
            snprintf(outVal, outValLen, "Capabilities");
            return parser_ok;
        case 3:
            snprintf(outKey, outKeyLen, "Of Key");
            char pubKey[64];
            uint16_t pubKey_size;
            CHECK_ERROR(parser_getJsonValueAsString("sender", pubKey, &pubKey_size));
            snprintf(outVal, pubKey_size + 1, "%s", pubKey);
            return parser_ok;
        case 4:
            snprintf(outKey, outKeyLen, "Paying Gas");
            snprintf(outVal, outValLen, "");
            return parser_ok;
        case 5:
            // TODO : Iterate over all the transfers
            snprintf(outKey, outKeyLen, "Transfer 1");
            char to[65];
            char from[65];
            char amount[10];
            uint16_t to_size;
            uint16_t from_size;
            uint16_t amount_size;
            CHECK_ERROR(parser_getTransactionParams(1, amount, &amount_size, from, &from_size, to, &to_size));

            snprintf(outVal, amount_size + from_size + to_size + 15, "%s from \"%s\" to \"%s\"", amount, from, to);

            return parser_ok;
        case 6:
            snprintf(outKey, outKeyLen, "On Chain");
            char chain[2];
            uint16_t chain_size;
            CHECK_ERROR(parser_getJsonValueAsString("chainId", chain, &chain_size));
            snprintf(outVal, chain_size + 1, "%s", chain);
            return parser_ok;
        case 7:
            snprintf(outKey, outKeyLen, "Using Gas");
            char gasLimit[10];
            char gasPrice[10];
            uint16_t gasLimit_size;
            uint16_t gasPrice_size;

            CHECK_ERROR(parser_getJsonValueAsString("gasLimit", gasLimit, &gasLimit_size));
            CHECK_ERROR(parser_getJsonValueAsString("gasPrice", gasPrice, &gasPrice_size));

            snprintf(outVal, 8, "at most");
            snprintf(outVal + strlen(outVal), gasLimit_size + 2, " %s", gasLimit);
            snprintf(outVal + strlen(outVal), 10, " at price");
            snprintf(outVal + strlen(outVal), gasPrice_size + 2, " %s", gasPrice);
            return parser_ok;
        case 8:
            snprintf(outKey, outKeyLen, "Transaction hash");
            uint8_t hash[BLAKE2B_OUTPUT_LEN] = {0};
            if (blake2b_hash((uint8_t *)ctx->buffer, ctx->bufferLen, hash) != zxerr_ok) {
                return parser_unexpected_error;
            }

            uint8_t base64_hash[44];
            base64_encode(base64_hash, 44, hash, sizeof(hash));

            // Make it base64 URL safe
            for (int i = 0; base64_hash[i] != '\0'; i++) {
                if (base64_hash[i] == '+') {
                    base64_hash[i] = '-';
                } else if (base64_hash[i] == '/') {
                    base64_hash[i] = '_';
                }
            }

            snprintf(outVal, sizeof(base64_hash), "%s", base64_hash);
            return parser_ok;
        case 9:
            snprintf(outKey, outKeyLen, "Sign for Address");
            /*
                Currently launching cpp tests, so this is not available
                uint8_t address[32];
                uint16_t address_size;
                CHECK_ERROR(crypto_fillAddress(address, sizeof(address), &address_size));
                snprintf(outVal, address_size + 1, "%s", address);
            */
            
            return parser_ok;
        default:
            break;
    }

    return parser_display_idx_out_of_range;
}
