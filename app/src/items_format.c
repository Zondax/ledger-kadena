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

#include "items_format.h"

#include <zxformat.h>

#include "crypto.h"
#include "parser.h"

extern char base64_hash[45];

items_error_t items_stdToDisplayString(item_t item, char *outVal, uint16_t outValLen) {
    const parsed_json_t *json_all = &(parser_getParserTxObj()->json);
    const jsmntok_t *token = &(json_all->tokens[item.json_token_index]);
    const uint16_t len = token->end - token->start;

    if (len == 0) return items_length_zero;

    if (len >= outValLen) {
        return items_data_too_large;
    }

    snprintf(outVal, outValLen, "%.*s", len, json_all->buffer + token->start);

    return items_ok;
}

items_error_t items_nothingToDisplayString(__Z_UNUSED item_t item, char *outVal, uint16_t outValLen) {
    char nothing[] = " ";
    uint16_t len = 2;

    if (len > outValLen) return items_data_too_large;

    snprintf(outVal, len, "%s", nothing);
    return items_ok;
}

items_error_t items_warningToDisplayString(__Z_UNUSED item_t item, char *outVal, uint16_t outValLen) {
    uint16_t len = sizeof(WARNING_TEXT);

    if (len > outValLen) return items_data_too_large;

    snprintf(outVal, len, WARNING_TEXT);
    return items_ok;
}

items_error_t items_cautionToDisplayString(__Z_UNUSED item_t item, char *outVal, uint16_t outValLen) {
    uint16_t len = sizeof(CAUTION_TEXT);

    if (len > outValLen) return items_data_too_large;

    snprintf(outVal, len, CAUTION_TEXT);
    return items_ok;
}

items_error_t items_txTooLargeToDisplayString(__Z_UNUSED item_t item, char *outVal, uint16_t outValLen) {
    uint16_t len = sizeof(TX_TOO_LARGE_TEXT);

    if (len > outValLen) return items_data_too_large;

    snprintf(outVal, len, TX_TOO_LARGE_TEXT);
    return items_ok;
}

items_error_t items_signingToDisplayString(__Z_UNUSED item_t item, char *outVal, uint16_t outValLen) {
    uint16_t len = sizeof("Transaction");

    if (len > outValLen) return items_data_too_large;

    snprintf(outVal, len, "Transaction");
    return items_ok;
}

items_error_t items_requiringToDisplayString(__Z_UNUSED item_t item, char *outVal, uint16_t outValLen) {
    uint16_t len = sizeof("Capabilities");

    if (len > outValLen) return items_data_too_large;

    snprintf(outVal, len, "Capabilities");
    return items_ok;
}

items_error_t items_transferToDisplayString(item_t item, char *outVal, uint16_t outValLen) {
    char amount[50];
    uint8_t amount_len = 0;
    char to[65];
    uint8_t to_len = 0;
    char from[65];
    uint8_t from_len = 0;
    uint16_t token_index = 0;
    parsed_json_t *json_all = &(parser_getParserTxObj()->json);
    uint16_t item_token_index = item.json_token_index;

    PARSER_TO_ITEMS_ERROR(object_get_value(json_all, item_token_index, "args", &token_index));

    PARSER_TO_ITEMS_ERROR(parser_arrayElementToString(token_index, 0, from, &from_len));

    PARSER_TO_ITEMS_ERROR(parser_arrayElementToString(token_index, 1, to, &to_len));

    PARSER_TO_ITEMS_ERROR(parser_arrayElementToString(token_index, 2, amount, &amount_len));

    outValLen = amount_len + from_len + to_len + sizeof(" from ") + sizeof(" to ") + 4 * sizeof("\"");
    snprintf(outVal, outValLen, "%s from \"%s\" to \"%s\"", amount, from, to);

    return items_ok;
}

items_error_t items_crossTransferToDisplayString(item_t item, char *outVal, uint16_t outValLen) {
    char amount[50];
    uint8_t amount_len = 0;
    char to[65];
    uint8_t to_len = 0;
    char from[65];
    uint8_t from_len = 0;
    char chain[3];
    uint8_t chain_len = 0;
    uint16_t token_index = 0;
    parsed_json_t *json_all = &(parser_getParserTxObj()->json);
    uint16_t item_token_index = item.json_token_index;

    PARSER_TO_ITEMS_ERROR(object_get_value(json_all, item_token_index, "args", &token_index));

    PARSER_TO_ITEMS_ERROR(parser_arrayElementToString(token_index, 0, from, &from_len));

    PARSER_TO_ITEMS_ERROR(parser_arrayElementToString(token_index, 1, to, &to_len));

    PARSER_TO_ITEMS_ERROR(parser_arrayElementToString(token_index, 2, amount, &amount_len));

    PARSER_TO_ITEMS_ERROR(parser_arrayElementToString(token_index, 3, chain, &chain_len));

    outValLen = amount_len + from_len + to_len + chain_len + sizeof("Cross-chain ") + sizeof(" from ") + sizeof(" to ") +
                6 * sizeof("\"") + sizeof(" to chain ");
    snprintf(outVal, outValLen, "Cross-chain %s from \"%s\" to \"%s\" to chain \"%s\"", amount, from, to, chain);

    return items_ok;
}

items_error_t items_rotateToDisplayString(item_t item, char *outVal, uint16_t outValLen) {
    uint16_t token_index = 0;
    uint16_t item_token_index = item.json_token_index;
    parsed_json_t *json_all = &(parser_getParserTxObj()->json);
    jsmntok_t *token;

    PARSER_TO_ITEMS_ERROR(object_get_value(json_all, item_token_index, "args", &token_index));
    PARSER_TO_ITEMS_ERROR(array_get_nth_element(json_all, token_index, 0, &token_index));
    token = &(json_all->tokens[token_index]);

    outValLen = token->end - token->start + sizeof("\"\"");
    snprintf(outVal, outValLen, "\"%s\"", json_all->buffer + token->start);

    return items_ok;
}

items_error_t items_gasToDisplayString(__Z_UNUSED item_t item, char *outVal, uint16_t outValLen) {
    char gasLimit[10];
    uint8_t gasLimit_len = 0;
    char gasPrice[64];
    uint8_t gasPrice_len = 0;
    parsed_json_t *json_all = &(parser_getParserTxObj()->json);
    uint16_t item_token_index = item.json_token_index;
    uint16_t meta_token_index = item.json_token_index;
    jsmntok_t *token;

    PARSER_TO_ITEMS_ERROR(object_get_value(json_all, item_token_index, JSON_GAS_LIMIT, &item_token_index));
    token = &(json_all->tokens[item_token_index]);

    gasLimit_len = token->end - token->start + 1;
    snprintf(gasLimit, gasLimit_len, "%s", json_all->buffer + token->start);

    item_token_index = meta_token_index;

    PARSER_TO_ITEMS_ERROR(object_get_value(json_all, item_token_index, JSON_GAS_PRICE, &item_token_index));
    token = &(json_all->tokens[item_token_index]);

    gasPrice_len = token->end - token->start + 1;
    snprintf(gasPrice, gasPrice_len, "%s", json_all->buffer + token->start);

    outValLen = gasLimit_len + gasPrice_len + sizeof("at most ") + sizeof(" at price ");
    snprintf(outVal, outValLen, "at most %s at price %s", gasLimit, gasPrice);

    return items_ok;
}

items_error_t items_hashToDisplayString(__Z_UNUSED item_t item, char *outVal, uint16_t outValLen) {
    outValLen = sizeof(base64_hash) - 1;
    snprintf(outVal, outValLen, "%s", base64_hash);
    return items_ok;
}

items_error_t items_unknownCapabilityToDisplayString(item_t item, char *outVal, uint16_t outValLen) {
    uint16_t token_index = 0;
    uint16_t args_count = 0;
    uint8_t outVal_idx = 0;
    parsed_json_t *json_all = &(parser_getParserTxObj()->json);
    uint16_t item_token_index = item.json_token_index;
    jsmntok_t *token;
    uint16_t len = 0;

    PARSER_TO_ITEMS_ERROR(object_get_value(json_all, item_token_index, "name", &token_index));
    token = &(json_all->tokens[token_index]);

    len = token->end - token->start;

    if (len == 0) return items_length_zero;

    len += sizeof("name: ");

    if (len >= outValLen) {
        return items_data_too_large;
    }

    snprintf(outVal, outValLen, "name: %.*s", len, json_all->buffer + token->start);
    outVal_idx += len;

    // Remove null terminator
    outVal[outVal_idx - 1] = ',';

    // Add space
    outVal[outVal_idx] = ' ';
    outVal_idx++;

    if (item.can_display == bool_false) {
        len = sizeof("args cannot be displayed on Ledger");
        snprintf(outVal + outVal_idx, len, "args cannot be displayed on Ledger");
        return items_ok;
    }

    PARSER_TO_ITEMS_ERROR(object_get_value(json_all, item_token_index, "args", &token_index));
    PARSER_TO_ITEMS_ERROR(array_get_element_count(json_all, token_index, &args_count));

    if (args_count) {
        uint16_t args_token_index = 0;
        for (uint8_t i = 0; i < (uint8_t)args_count - 1; i++) {
            PARSER_TO_ITEMS_ERROR(array_get_nth_element(json_all, token_index, i, &args_token_index));
            token = &(json_all->tokens[args_token_index]);

            len = token->end - token->start + (token->type == JSMN_STRING ? sizeof("arg X: \"\",") : sizeof("arg X: ,"));

            // Strings go in between double quotes
            snprintf(outVal + outVal_idx, len, (token->type == JSMN_STRING) ? "arg %d: \"%s\"," : "arg %d: %s,", i + 1,
                     json_all->buffer + token->start);

            outVal_idx += len;
            outVal[outVal_idx - 1] = ' ';  // Remove null terminator
        }

        // Last arg (without comma)
        PARSER_TO_ITEMS_ERROR(array_get_nth_element(json_all, token_index, args_count - 1, &args_token_index));
        token = &(json_all->tokens[args_token_index]);

        len = token->end - token->start + (token->type == JSMN_STRING ? sizeof("arg X: \"\"") : sizeof("arg X: "));

        snprintf(outVal + outVal_idx, len, (token->type == JSMN_STRING) ? "arg %d: \"%s\"" : "arg %d: %s", args_count,
                 json_all->buffer + token->start);
    } else {
        len = sizeof("no args");
        snprintf(outVal + outVal_idx, len, "no args");
    }

    return items_ok;
}

#if defined(TARGET_NANOS) || defined(TARGET_NANOX) || defined(TARGET_NANOS2) || defined(TARGET_STAX) || defined(TARGET_FLEX)
items_error_t items_signForAddrToDisplayString(__Z_UNUSED item_t item, char *outVal, uint16_t outValLen) {
    uint8_t address[65];
    uint16_t address_len;

    if (crypto_fillAddress(address, sizeof(address), &address_len) != zxerr_ok) {
        return items_error;
    }

    outValLen = sizeof(address);
    array_to_hexstr(outVal, outValLen, address, PUB_KEY_LENGTH);

    return items_ok;
}
#endif