
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
#include "crypto_helper.h"
#include "items.h"
#include "parser_impl.h"
#include <base64.h>

static parser_error_t items_stdToDisplayString(parsed_json_t json_obj, char *outVal, uint16_t *outValLen);
static parser_error_t items_signingToDisplayString(parsed_json_t json_obj, char *outVal, uint16_t *outValLen);
static parser_error_t items_requiringToDisplayString(parsed_json_t json_obj, char *outVal, uint16_t *outValLen);
static parser_error_t items_transferToDisplayString(parsed_json_t json_obj, char *outVal, uint16_t *outValLen);
static parser_error_t items_gasToDisplayString(parsed_json_t json_obj, char *outVal, uint16_t *outValLen);
static parser_error_t items_unknownCapabilityToDisplayString(parsed_json_t json_obj, char *outVal, uint16_t *outValLen);
static void items_storeGasItem(parsed_json_t *json_gas_obj, uint8_t items_idx, uint8_t *unknown_capabitilies);
static void items_storeTransferItem(parsed_json_t *json_possible_transfer, uint8_t items_idx, uint8_t *num_of_transfers, uint8_t *unknown_capabitilies);

#define CURR_ITEM_JSON item_array.items[items_idx].json

item_array_t item_array;

parsed_json_t signing_json;
parsed_json_t requiring_json;

uint8_t hash[BLAKE2B_HASH_SIZE] = {0};
char base64_hash[44];

void items_initItems() {
    MEMZERO(&item_array, sizeof(item_array_t));
    MEMZERO(&signing_json, sizeof(parsed_json_t));
    MEMZERO(&requiring_json, sizeof(parsed_json_t));
}

item_array_t *items_getItemArray() {
    return &item_array;
}

void items_storeItems() {
    parsed_json_t json_clist;
    parsed_json_t json_possible_transfer;
    uint8_t items_idx = 0;
    uint8_t unknown_capabitilies = 1;
    uint8_t num_of_transfers = 1;
    uint16_t token_index = 0;

    strcpy(item_array.items[items_idx].key, "Signing");
    item_array.items[items_idx].toString = items_signingToDisplayString;
    items_idx++;

    // Skip item if network id is not available
    if (parser_getJsonValue(&CURR_ITEM_JSON, JSON_NETWORK_ID) == parser_ok) {
        strcpy(item_array.items[items_idx].key, "On Network");
        item_array.items[items_idx].toString = items_stdToDisplayString;
        items_idx++;
    }

    strcpy(item_array.items[items_idx].key, "Requiring");
    item_array.items[items_idx].toString = items_requiringToDisplayString;
    items_idx++;

    if (parser_getJsonValue(&CURR_ITEM_JSON, JSON_META) == parser_ok) {
        if (parser_getJsonValue(&CURR_ITEM_JSON, JSON_SENDER) == parser_ok) {
            strcpy(item_array.items[items_idx].key, "Of Key");
            item_array.items[items_idx].toString = items_stdToDisplayString;
            items_idx++;
        }
    }

    if (parser_getJsonValue(&CURR_ITEM_JSON, JSON_SIGNERS) == parser_ok) {
        if (parser_getJsonValue(&json_clist, JSON_CLIST) == parser_ok) {
            parser_getGasObject(&json_clist);
            items_storeGasItem(&json_clist, items_idx, &unknown_capabitilies);
            items_idx++;
        }
    }

    if (parser_getJsonValue(&json_clist, JSON_SIGNERS) == parser_ok) {
        if (parser_getJsonValue(&json_clist, JSON_CLIST) == parser_ok) {
            for (uint8_t i = 0; i < parser_getNumberOfClistElements(); i++) {
                if (array_get_nth_element(&json_clist, 0, i, &token_index) == parser_ok) {
                    json_parse(&json_possible_transfer, json_clist.buffer + json_clist.tokens[token_index].start,
                    json_clist.tokens[token_index].end - json_clist.tokens[token_index].start);

                    if (object_get_value(&json_possible_transfer, 0, "name", &token_index) == parser_ok) {
                        if (MEMCMP("coin.TRANSFER", json_possible_transfer.buffer + json_possible_transfer.tokens[token_index].start,
                                json_possible_transfer.tokens[token_index].end - json_possible_transfer.tokens[token_index].start) == 0) {
                            items_storeTransferItem(&json_possible_transfer, items_idx, &num_of_transfers, &unknown_capabitilies);
                            items_idx++;
                        }
                    }
                }
            }
        }
    }

    if (parser_getJsonValue(&CURR_ITEM_JSON, JSON_META) == parser_ok) {
        if (parser_getJsonValue(&CURR_ITEM_JSON, JSON_CHAIN_ID) == parser_ok) {
            strcpy(item_array.items[items_idx].key, "On Chain");
            item_array.items[items_idx].toString = items_stdToDisplayString;
            items_idx++;
        }
    }

    if (parser_getJsonValue(&CURR_ITEM_JSON, JSON_META) == parser_ok) {
        strcpy(item_array.items[items_idx].key, "Using Gas");
        item_array.items[items_idx].toString = items_gasToDisplayString;
        items_idx++;
    }

    strcpy(item_array.items[items_idx].key, "Transaction hash");
    if (blake2b_hash((uint8_t *)parser_getParserTxObj()->tx_json.json.buffer, parser_getParserTxObj()->tx_json.json.bufferLen, hash) != zxerr_ok) {
        return ;
    }

    base64_encode(base64_hash, 44, hash, sizeof(hash));

    // Make it base64 URL safe
    for (int i = 0; base64_hash[i] != '\0'; i++) {
        if (base64_hash[i] == '+') {
            base64_hash[i] = '-';
        } else if (base64_hash[i] == '/') {
            base64_hash[i] = '_';
        }
    }

    CURR_ITEM_JSON.buffer = base64_hash;
    CURR_ITEM_JSON.bufferLen = sizeof(base64_hash) - 1;
    item_array.items[items_idx].toString = items_stdToDisplayString;
    items_idx++;

    /*
    strcpy(item_array.items[items_idx].key, "Sign for Address");
    Currently launching cpp tests, so this is not available
    uint8_t address[32];
    uint16_t address_size;
    CHECK_ERROR(crypto_fillAddress(address, sizeof(address), &address_size));
    snprintf(outVal, address_size + 1, "%s", address);
    item_array.items[items_idx].toString = items_stdToDisplayString;
    items_idx++;
    */

    item_array.numOfItems = items_idx;
}

uint16_t items_getTotalItems() {
    return item_array.numOfItems;
}

static void items_storeGasItem(parsed_json_t *json_gas_obj, uint8_t items_idx, uint8_t *unknown_capabitilies) {
    uint16_t token_index = 0;
    uint16_t args_count = 0;
    parsed_json_t args_json;

    CURR_ITEM_JSON = *json_gas_obj;
    object_get_value(json_gas_obj, 0, "args", &token_index);
    json_parse(&args_json, json_gas_obj->buffer + json_gas_obj->tokens[token_index].start,
        json_gas_obj->tokens[token_index].end - json_gas_obj->tokens[token_index].start);
    array_get_element_count(&args_json, 0, &args_count);

    if (args_count > 0) {
        snprintf(item_array.items[items_idx].key, sizeof(item_array.items[items_idx].key), "Unknown Capability %d", *unknown_capabitilies);
        (*unknown_capabitilies)++;
        item_array.items[items_idx].toString = items_unknownCapabilityToDisplayString;
    } else {
        strcpy(item_array.items[items_idx].key, "Paying Gas");
        item_array.items[items_idx].json.bufferLen = 0;
        item_array.items[items_idx].toString = items_stdToDisplayString;
    }
}

static void items_storeTransferItem(parsed_json_t *json_possible_transfer, uint8_t items_idx, uint8_t *num_of_transfers, uint8_t *unknown_capabitilies) {
    uint16_t token_index = 0;
    uint16_t num_of_args = 0;
    parsed_json_t args_json;

    CURR_ITEM_JSON = *json_possible_transfer;

    object_get_value(json_possible_transfer, 0, "args", &token_index);
    json_parse(&args_json, json_possible_transfer->buffer + json_possible_transfer->tokens[token_index].start,
        json_possible_transfer->tokens[token_index].end - json_possible_transfer->tokens[token_index].start);

    array_get_element_count(&args_json, 0, &num_of_args);

    if (num_of_args == 3) {
        snprintf(item_array.items[items_idx].key, sizeof(item_array.items[items_idx].key), "Transfer %d", *num_of_transfers);
        (*num_of_transfers)++;
        item_array.items[items_idx].toString = items_transferToDisplayString;
    } else {
        snprintf(item_array.items[items_idx].key, sizeof(item_array.items[items_idx].key), "Unknown Capability %d", *unknown_capabitilies);
        (*unknown_capabitilies)++;
        item_array.items[items_idx].toString = items_unknownCapabilityToDisplayString;
    }
}

static parser_error_t items_stdToDisplayString(__Z_UNUSED parsed_json_t json_obj, char *outVal, uint16_t *outValLen) {
    *outValLen = json_obj.bufferLen + 1;
    snprintf(outVal, *outValLen, "%s", json_obj.buffer);
    return parser_ok;
}

static parser_error_t items_signingToDisplayString(__Z_UNUSED parsed_json_t json_obj, char *outVal, uint16_t *outValLen) {
    *outValLen = sizeof("Transaction");
    snprintf(outVal, *outValLen, "Transaction");
    return parser_ok;
}

static parser_error_t items_requiringToDisplayString(__Z_UNUSED parsed_json_t json_obj, char *outVal, uint16_t *outValLen) {
    *outValLen = sizeof("Capabilities");
    snprintf(outVal, *outValLen, "Capabilities");
    return parser_ok;
}

static parser_error_t items_transferToDisplayString(parsed_json_t json_obj, char *outVal, uint16_t *outValLen) {
    char amount[50];
    uint8_t amount_len = 0;
    char to[65];
    uint8_t to_len = 0;
    char from[65];
    uint8_t from_len = 0;
    uint16_t token_index = 0;
    parsed_json_t args_json;

    object_get_value(&json_obj, 0, "args", &token_index);
    json_parse(&args_json, json_obj.buffer + json_obj.tokens[token_index].start,
        json_obj.tokens[token_index].end - json_obj.tokens[token_index].start);
    array_get_nth_element(&args_json, 0, 0, &token_index);
    strncpy(from, args_json.buffer + args_json.tokens[token_index].start, args_json.tokens[token_index].end - args_json.tokens[token_index].start);
    from_len = args_json.tokens[token_index].end - args_json.tokens[token_index].start;
    from[from_len] = '\0';

    array_get_nth_element(&args_json, 0, 1, &token_index);
    strncpy(to, args_json.buffer + args_json.tokens[token_index].start, args_json.tokens[token_index].end - args_json.tokens[token_index].start);
    to_len = args_json.tokens[token_index].end - args_json.tokens[token_index].start;
    to[to_len] = '\0';

    array_get_nth_element(&args_json, 0, 2, &token_index);
    strncpy(amount, args_json.buffer + args_json.tokens[token_index].start, args_json.tokens[token_index].end - args_json.tokens[token_index].start);
    amount_len = args_json.tokens[token_index].end - args_json.tokens[token_index].start;
    amount[amount_len] = '\0';

    *outValLen = amount_len + from_len + to_len + sizeof(" from ") + sizeof(" to ") + 4 * sizeof("\"");
    snprintf(outVal, *outValLen, "%s from \"%s\" to \"%s\"", amount, from, to);

    return parser_ok;
}

static parser_error_t items_gasToDisplayString(__Z_UNUSED parsed_json_t json_obj, char *outVal, uint16_t *outValLen) {
    char gasLimit[10];
    uint8_t gasLimit_len = 0;
    char gasPrice[64];
    uint8_t gasPrice_len = 0;
    parsed_json_t gas_json_obj;

    parser_getJsonValue(&gas_json_obj, JSON_GAS_LIMIT);
    gasLimit_len = gas_json_obj.bufferLen + 1;
    snprintf(gasLimit, gasLimit_len, "%s", gas_json_obj.buffer);

    parser_getJsonValue(&gas_json_obj, JSON_GAS_PRICE);
    gasPrice_len = gas_json_obj.bufferLen + 1;
    snprintf(gasPrice, gasPrice_len, "%s", gas_json_obj.buffer);

    *outValLen = gasLimit_len + gasPrice_len + sizeof("at most ") + sizeof(" at price ");
    snprintf(outVal, *outValLen, "at most %s at price %s", gasLimit, gasPrice);

    return parser_ok;
}

static parser_error_t items_unknownCapabilityToDisplayString(parsed_json_t json_obj, char *outVal, uint16_t *outValLen) {
    uint16_t token_index = 0;
    uint16_t args_count = 0;
    uint8_t len = 0;
    uint8_t outVal_idx= 0;
    parsed_json_t args_json;

    object_get_value(&json_obj, 0, "name", &token_index);
    len = json_obj.tokens[token_index].end - json_obj.tokens[token_index].start + sizeof("name: ");
    snprintf(outVal, len, "name: %s", json_obj.buffer + json_obj.tokens[token_index].start);
    outVal_idx += len;

    // Remove null terminator
    outVal[outVal_idx - 1] = ',';
    
    // Add space
    outVal[outVal_idx] = ' ';
    outVal_idx++;

    object_get_value(&json_obj, 0, "args", &token_index);
    json_parse(&args_json, json_obj.buffer + json_obj.tokens[token_index].start,
        json_obj.tokens[token_index].end - json_obj.tokens[token_index].start);
    array_get_element_count(&args_json, 0, &args_count);

    for (uint8_t i = 0; i < args_count - 1; i++) {
        array_get_nth_element(&args_json, 0, i, &token_index);
        if (args_json.tokens[token_index].type == JSMN_STRING) {
            // Strings go in between double quotes
            len = args_json.tokens[token_index].end - args_json.tokens[token_index].start + sizeof("arg X: \"\",");
            snprintf(outVal + outVal_idx, len, "arg %d: \"%s\",", i + 1, args_json.buffer + args_json.tokens[token_index].start);
        } else {
            len = args_json.tokens[token_index].end - args_json.tokens[token_index].start + sizeof("arg X: ,");
            snprintf(outVal + outVal_idx, len, "arg %d: %s,", i + 1, args_json.buffer + args_json.tokens[token_index].start);
        }
        outVal_idx += len;

        // Remove null terminator
        outVal[outVal_idx - 1] = ' ';
    }
    
    // Last arg (without comma)
    array_get_nth_element(&args_json, 0, args_count - 1, &token_index);
    if (args_json.tokens[token_index].type == JSMN_STRING) {
        len = args_json.tokens[token_index].end - args_json.tokens[token_index].start + sizeof("arg X: \"\"");
        snprintf(outVal + outVal_idx, len, "arg %d: \"%s\"", args_count, args_json.buffer + args_json.tokens[token_index].start);
    } else {
        len = args_json.tokens[token_index].end - args_json.tokens[token_index].start + sizeof("arg X: ");
        snprintf(outVal + outVal_idx, len, "arg %d: %s", args_count, args_json.buffer + args_json.tokens[token_index].start);
    }

    outVal_idx += len;

    *outValLen = outVal_idx;

    return parser_ok;
}