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
#include "parser.h"

extern char base64_hash[44];

items_error_t items_stdToDisplayString(item_t item, char *outVal, uint16_t *outValLen) {
    parsed_json_t json_all = parser_getParserTxObj()->tx_json.json;
    uint16_t item_token_index = item.json_token_index;

    *outValLen = json_all.tokens[item_token_index].end - json_all.tokens[item_token_index].start + 1;
    snprintf(outVal, *outValLen, "%s", json_all.buffer + json_all.tokens[item_token_index].start);

    return items_ok;
}

items_error_t items_nothingToDisplayString(__Z_UNUSED item_t item, char *outVal, uint16_t *outValLen) {
    *outValLen = 1;
    snprintf(outVal, *outValLen, " ");
    return items_ok;
}

items_error_t items_warningToDisplayString(__Z_UNUSED item_t item, char *outVal, uint16_t *outValLen) {
    *outValLen = sizeof(WARNING_TEXT);
    snprintf(outVal, *outValLen, WARNING_TEXT);
    return items_ok;
}

items_error_t items_cautionToDisplayString(__Z_UNUSED item_t item, char *outVal, uint16_t *outValLen) {
    *outValLen = sizeof(CAUTION_TEXT);
    snprintf(outVal, *outValLen, CAUTION_TEXT);
    return items_ok;
}

items_error_t items_txTooLargeToDisplayString(__Z_UNUSED item_t item, char *outVal, uint16_t *outValLen) {
    *outValLen = sizeof(TX_TOO_LARGE_TEXT);
    snprintf(outVal, *outValLen, TX_TOO_LARGE_TEXT);
    return items_ok;
}

items_error_t items_signingToDisplayString(__Z_UNUSED item_t item, char *outVal, uint16_t *outValLen) {
    *outValLen = sizeof("Transaction");
    snprintf(outVal, *outValLen, "Transaction");
    return items_ok;
}

items_error_t items_requiringToDisplayString(__Z_UNUSED item_t item, char *outVal, uint16_t *outValLen) {
    *outValLen = sizeof("Capabilities");
    snprintf(outVal, *outValLen, "Capabilities");
    return items_ok;
}

items_error_t items_transferToDisplayString(item_t item, char *outVal, uint16_t *outValLen) {
    char amount[50];
    uint8_t amount_len = 0;
    char to[65];
    uint8_t to_len = 0;
    char from[65];
    uint8_t from_len = 0;
    uint16_t token_index = 0;
    parsed_json_t json_all = parser_getParserTxObj()->tx_json.json;
    uint16_t item_token_index = item.json_token_index;

    object_get_value(&json_all, item_token_index, "args", &token_index);

    PARSER_TO_ITEMS_ERROR(parser_arrayElementToString(token_index, 0, from, &from_len));

    PARSER_TO_ITEMS_ERROR(parser_arrayElementToString(token_index, 1, to, &to_len));

    PARSER_TO_ITEMS_ERROR(parser_arrayElementToString(token_index, 2, amount, &amount_len));

    *outValLen = amount_len + from_len + to_len + sizeof(" from ") + sizeof(" to ") + 4 * sizeof("\"");
    snprintf(outVal, *outValLen, "%s from \"%s\" to \"%s\"", amount, from, to);

    return items_ok;
}

items_error_t items_crossTransferToDisplayString(item_t item, char *outVal, uint16_t *outValLen) {
    char amount[50];
    uint8_t amount_len = 0;
    char to[65];
    uint8_t to_len = 0;
    char from[65];
    uint8_t from_len = 0;
    char chain[3];
    uint8_t chain_len = 0;
    uint16_t token_index = 0;
    parsed_json_t json_all = parser_getParserTxObj()->tx_json.json;
    uint16_t item_token_index = item.json_token_index;

    object_get_value(&json_all, item_token_index, "args", &token_index);

    PARSER_TO_ITEMS_ERROR(parser_arrayElementToString(token_index, 0, from, &from_len));

    PARSER_TO_ITEMS_ERROR(parser_arrayElementToString(token_index, 1, to, &to_len));

    PARSER_TO_ITEMS_ERROR(parser_arrayElementToString(token_index, 2, amount, &amount_len));

    PARSER_TO_ITEMS_ERROR(parser_arrayElementToString(token_index, 3, chain, &chain_len));

    *outValLen = amount_len + from_len + to_len + chain_len + sizeof("Cross-chain ") + sizeof(" from ") + sizeof(" to ") + 6 * sizeof("\"") + sizeof(" to chain ");
    snprintf(outVal, *outValLen, "Cross-chain %s from \"%s\" to \"%s\" to chain \"%s\"", amount, from, to, chain);

    return items_ok;
}

items_error_t items_rotateToDisplayString(item_t item, char *outVal, uint16_t *outValLen) {
    uint16_t token_index = 0;
    uint16_t item_token_index = item.json_token_index;
    parsed_json_t json_all = parser_getParserTxObj()->tx_json.json;

    object_get_value(&json_all, item_token_index, "args", &token_index);
    array_get_nth_element(&json_all, token_index, 0, &token_index);

    *outValLen = json_all.tokens[token_index].end - json_all.tokens[token_index].start + sizeof("\"\"");
    snprintf(outVal, *outValLen, "\"%s\"", json_all.buffer + json_all.tokens[token_index].start);

    return items_ok;
}

items_error_t items_gasToDisplayString(__Z_UNUSED item_t item, char *outVal, uint16_t *outValLen) {
    char gasLimit[10];
    uint8_t gasLimit_len = 0;
    char gasPrice[64];
    uint8_t gasPrice_len = 0;
    parsed_json_t json_all = parser_getParserTxObj()->tx_json.json;
    uint16_t item_token_index = item.json_token_index;
    uint16_t meta_token_index = item_token_index;

    parser_getJsonValue(&item_token_index, JSON_GAS_LIMIT);
    gasLimit_len = json_all.tokens[item_token_index].end - json_all.tokens[item_token_index].start + 1;
    snprintf(gasLimit, gasLimit_len, "%s", json_all.buffer + json_all.tokens[item_token_index].start);

    item_token_index = meta_token_index;
    parser_getJsonValue(&item_token_index, JSON_GAS_PRICE);
    gasPrice_len = json_all.tokens[item_token_index].end - json_all.tokens[item_token_index].start + 1;
    snprintf(gasPrice, gasPrice_len, "%s", json_all.buffer + json_all.tokens[item_token_index].start);

    *outValLen = gasLimit_len + gasPrice_len + sizeof("at most ") + sizeof(" at price ");
    snprintf(outVal, *outValLen, "at most %s at price %s", gasLimit, gasPrice);

    return items_ok;
}

items_error_t items_hashToDisplayString(__Z_UNUSED item_t item, char *outVal, uint16_t *outValLen) {
    *outValLen = sizeof(base64_hash);
    snprintf(outVal, *outValLen, "%s", base64_hash);
    return items_ok;
}

items_error_t items_unknownCapabilityToDisplayString(item_t item, char *outVal, uint16_t *outValLen) {
    uint16_t token_index = 0;
    uint16_t args_count = 0;
    uint8_t len = 0;
    uint8_t outVal_idx= 0;
    parsed_json_t json_all = parser_getParserTxObj()->tx_json.json;
    uint16_t item_token_index = item.json_token_index;

    object_get_value(&json_all, item_token_index, "name", &token_index);
    len = json_all.tokens[token_index].end - json_all.tokens[token_index].start + sizeof("name: ");
    snprintf(outVal, len, "name: %s", json_all.buffer + json_all.tokens[token_index].start);
    outVal_idx += len;

    // Remove null terminator
    outVal[outVal_idx - 1] = ',';
    
    // Add space
    outVal[outVal_idx] = ' ';
    outVal_idx++;

    if (item.can_display == bool_false) {
        len = sizeof("args cannot be displayed on Ledger");
        snprintf(outVal + outVal_idx, len, "args cannot be displayed on Ledger");
        outVal_idx += len;
        return items_ok;
    }

    object_get_value(&json_all, item_token_index, "args", &token_index);
    array_get_element_count(&json_all, token_index, &args_count);


    if (args_count) {
        uint16_t args_token_index = 0;
        for (uint8_t i = 0; i < args_count - 1; i++) {
            array_get_nth_element(&json_all, token_index, i, &args_token_index);
            if (json_all.tokens[args_token_index].type == JSMN_STRING) {
                // Strings go in between double quotes
                len = json_all.tokens[args_token_index].end - json_all.tokens[args_token_index].start + sizeof("arg X: \"\",");
                snprintf(outVal + outVal_idx, len, "arg %d: \"%s\",", i + 1, json_all.buffer + json_all.tokens[args_token_index].start);
            } else {
                len = json_all.tokens[args_token_index].end - json_all.tokens[args_token_index].start + sizeof("arg X: ,");
                snprintf(outVal + outVal_idx, len, "arg %d: %s,", i + 1, json_all.buffer + json_all.tokens[args_token_index].start);
            }
            outVal_idx += len;

            // Remove null terminator
            outVal[outVal_idx - 1] = ' ';
        }
        
        // Last arg (without comma)
        array_get_nth_element(&json_all, token_index, args_count - 1, &args_token_index);
        if (json_all.tokens[args_token_index].type == JSMN_STRING) {
            len = json_all.tokens[args_token_index].end - json_all.tokens[args_token_index].start + sizeof("arg X: \"\"");
            snprintf(outVal + outVal_idx, len, "arg %d: \"%s\"", args_count, json_all.buffer + json_all.tokens[args_token_index].start);
        } else {
            len = json_all.tokens[args_token_index].end - json_all.tokens[args_token_index].start + sizeof("arg X: ");
            snprintf(outVal + outVal_idx, len, "arg %d: %s", args_count, json_all.buffer + json_all.tokens[args_token_index].start);
        }
        outVal_idx += len;
    } else {
        len = sizeof("no args");
        snprintf(outVal + outVal_idx, len, "no args");
        outVal_idx += len;
    }

    *outValLen = outVal_idx;

    return items_ok;
}