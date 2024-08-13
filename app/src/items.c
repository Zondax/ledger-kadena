
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

static parser_error_t items_stdToDisplayString(uint16_t token_index, char *outVal, uint16_t *outValLen);
static parser_error_t items_nothingToDisplayString(__Z_UNUSED uint16_t token_index, char *outVal, uint16_t *outValLen);
static parser_error_t items_warningToDisplayString(__Z_UNUSED uint16_t token_index, char *outVal, uint16_t *outValLen);
static parser_error_t items_signingToDisplayString(uint16_t token_index, char *outVal, uint16_t *outValLen);
static parser_error_t items_requiringToDisplayString(uint16_t token_index, char *outVal, uint16_t *outValLen);
static parser_error_t items_transferToDisplayString(uint16_t token_index, char *outVal, uint16_t *outValLen);
static parser_error_t items_rotateToDisplayString(uint16_t token_index_json, char *outVal, uint16_t *outValLen);
static parser_error_t items_gasToDisplayString(uint16_t token_index, char *outVal, uint16_t *outValLen);
static parser_error_t items_hashToDisplayString(uint16_t token_index, char *outVal, uint16_t *outValLen);
static parser_error_t items_unknownCapabilityToDisplayString(uint16_t token_index, char *outVal, uint16_t *outValLen);
static void items_storeGasItem(uint16_t json_token_index, uint8_t items_idx, uint8_t *unknown_capabitilies);
static void items_storeTransferItem(parsed_json_t *json_all, uint16_t transfer_token_index, uint8_t items_idx, uint8_t *num_of_transfers, uint8_t *unknown_capabitilies);
static void items_storeRotateItem(parsed_json_t *json_all, uint16_t transfer_token_index, uint8_t items_idx, uint8_t *unknown_capabitilies);

#define CURR_ITEM_TOKEN item_array.items[items_idx].json_token_index

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
    parsed_json_t json_all = parser_getParserTxObj()->tx_json.json;
    uint8_t items_idx = 0;
    uint8_t unknown_capabitilies = 1;
    uint8_t num_of_transfers = 1;
    uint16_t token_index = 0;
    bool unscoped_signer = false;

    strcpy(item_array.items[items_idx].key, "Signing");
    item_array.items[items_idx].toString = items_signingToDisplayString;
    items_idx++;

    // Skip item if network id is not available
    if (parser_getJsonValue(&CURR_ITEM_TOKEN, JSON_NETWORK_ID) == parser_ok) {
        strcpy(item_array.items[items_idx].key, "On Network");
        item_array.items[items_idx].toString = items_stdToDisplayString;
        items_idx++;
    }

    strcpy(item_array.items[items_idx].key, "Requiring");
    item_array.items[items_idx].toString = items_requiringToDisplayString;
    items_idx++;

    if (parser_getJsonValue(&CURR_ITEM_TOKEN, JSON_META) == parser_ok) {
        if (parser_getJsonValue(&CURR_ITEM_TOKEN, JSON_SENDER) == parser_ok) {
            strcpy(item_array.items[items_idx].key, "Of Key");
            item_array.items[items_idx].toString = items_stdToDisplayString;
            items_idx++;
        }
    }

    // TODO : Cleanup
    if (parser_getJsonValue(&CURR_ITEM_TOKEN, JSON_SIGNERS) == parser_ok) {
        array_get_nth_element(&json_all, CURR_ITEM_TOKEN, 0, &CURR_ITEM_TOKEN);
        if (parser_getJsonValue(&CURR_ITEM_TOKEN, JSON_CLIST) == parser_ok) {
            uint16_t clist_token_index = CURR_ITEM_TOKEN;
            for (uint8_t i = 0; i < parser_getNumberOfClistElements(); i++) {
                if (array_get_nth_element(&json_all, clist_token_index, i, &token_index) == parser_ok) {
                    uint16_t name_token_index = 0;
                    if (object_get_value(&json_all, token_index, JSON_NAME, &name_token_index) == parser_ok) {
                        if (MEMCMP("coin.TRANSFER", json_all.buffer + json_all.tokens[name_token_index].start,
                                json_all.tokens[name_token_index].end - json_all.tokens[name_token_index].start) == 0) {
                            if (parser_findKeyInClist(item_array.items[items_idx - 1].json_token_index) == parser_no_data) {
                                unscoped_signer = true;
                                break;
                            }
                        } 
                    }
                }
            }
        } else {
            // No Clist given
            unscoped_signer = true;
        }
    }

    if (unscoped_signer) {
        strcpy(item_array.items[items_idx].key, "Unscoped Signer");
        CURR_ITEM_TOKEN = item_array.items[items_idx - 1].json_token_index;
        item_array.items[items_idx].toString = items_stdToDisplayString;
        items_idx++;
    }

    CURR_ITEM_TOKEN = 0;
    if (parser_getJsonValue(&CURR_ITEM_TOKEN, JSON_SIGNERS) == parser_ok) {
        array_get_nth_element(&json_all, CURR_ITEM_TOKEN, 0, &CURR_ITEM_TOKEN);
        if (parser_getJsonValue(&CURR_ITEM_TOKEN, JSON_CLIST) == parser_ok) {
            parser_getGasObject(&CURR_ITEM_TOKEN);
            items_storeGasItem(CURR_ITEM_TOKEN, items_idx, &unknown_capabitilies);
            items_idx++;
        }
    }

    CURR_ITEM_TOKEN = 0;
    if (parser_getJsonValue(&CURR_ITEM_TOKEN, JSON_SIGNERS) == parser_ok) {
        array_get_nth_element(&json_all, CURR_ITEM_TOKEN, 0, &CURR_ITEM_TOKEN);
        if (parser_getJsonValue(&CURR_ITEM_TOKEN, JSON_CLIST) == parser_ok) {
            uint16_t clist_token_index = CURR_ITEM_TOKEN;
            for (uint8_t i = 0; i < parser_getNumberOfClistElements(); i++) {
                if (array_get_nth_element(&json_all, clist_token_index, i, &token_index) == parser_ok) {
                    uint16_t name_token_index = 0;
                    if (object_get_value(&json_all, token_index, JSON_NAME, &name_token_index) == parser_ok) {
                        if (MEMCMP("coin.TRANSFER", json_all.buffer + json_all.tokens[name_token_index].start,
                                json_all.tokens[name_token_index].end - json_all.tokens[name_token_index].start) == 0) {
                            CURR_ITEM_TOKEN = token_index;
                            items_storeTransferItem(&json_all, token_index, items_idx, &num_of_transfers, &unknown_capabitilies);
                            items_idx++;
                        } else if (MEMCMP("coin.ROTATE", json_all.buffer + json_all.tokens[name_token_index].start,
                                json_all.tokens[name_token_index].end - json_all.tokens[name_token_index].start) == 0) {
                            CURR_ITEM_TOKEN = token_index;
                            items_storeRotateItem(&json_all, token_index, items_idx, &unknown_capabitilies);
                            items_idx++;
                        }
                    }
                }
            }
        } else {
            // No Clist given, Raise warning
            strcpy(item_array.items[items_idx].key, "WARNING");
            item_array.items[items_idx].toString = items_warningToDisplayString;
            items_idx++;
        }
    }

    CURR_ITEM_TOKEN = 0;
    if (parser_getJsonValue(&CURR_ITEM_TOKEN, JSON_META) == parser_ok) {
        if (parser_getJsonValue(&CURR_ITEM_TOKEN, JSON_CHAIN_ID) == parser_ok) {
            strcpy(item_array.items[items_idx].key, "On Chain");
            item_array.items[items_idx].toString = items_stdToDisplayString;
            items_idx++;
        }
    }

    CURR_ITEM_TOKEN = 0;
    if (parser_getJsonValue(&CURR_ITEM_TOKEN, JSON_META) == parser_ok) {
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

    item_array.items[items_idx].toString = items_hashToDisplayString;
    items_idx++;

    strcpy(item_array.items[items_idx].key, "Sign for Address");
    /*
    Currently launching cpp tests, so this is not available
    uint8_t address[32];
    uint16_t address_size;
    CHECK_ERROR(crypto_fillAddress(address, sizeof(address), &address_size));
    snprintf(outVal, address_size + 1, "%s", address);
    */
    item_array.items[items_idx].toString = items_hashToDisplayString;
    items_idx++;

    item_array.numOfItems = items_idx;
}

uint16_t items_getTotalItems() {
    return item_array.numOfItems;
}

static void items_storeGasItem(uint16_t json_token_index, uint8_t items_idx, uint8_t *unknown_capabitilies) {
    uint16_t token_index = 0;
    uint16_t args_count = 0;
    parsed_json_t json_all = parser_getParserTxObj()->tx_json.json;

    object_get_value(&json_all, json_token_index, "args", &token_index);
    array_get_element_count(&json_all, token_index, &args_count);

    if (args_count > 0) {
        snprintf(item_array.items[items_idx].key, sizeof(item_array.items[items_idx].key), "Unknown Capability %d", *unknown_capabitilies);
        (*unknown_capabitilies)++;
        item_array.items[items_idx].toString = items_unknownCapabilityToDisplayString;
    } else {
        strcpy(item_array.items[items_idx].key, "Paying Gas");
        item_array.items[items_idx].toString = items_nothingToDisplayString;
    }
}

static void items_storeTransferItem(parsed_json_t *json_all, uint16_t transfer_token_index, uint8_t items_idx, uint8_t *num_of_transfers, uint8_t *unknown_capabitilies) {
    uint16_t token_index = 0;
    uint16_t num_of_args = 0;

    object_get_value(json_all, transfer_token_index, "args", &token_index);

    array_get_element_count(json_all, token_index, &num_of_args);

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

static void items_storeRotateItem(parsed_json_t *json_all, uint16_t transfer_token_index, uint8_t items_idx, uint8_t *unknown_capabitilies) {
    uint16_t token_index = 0;
    uint16_t num_of_args = 0;

    object_get_value(json_all, transfer_token_index, "args", &token_index);

    array_get_element_count(json_all, token_index, &num_of_args);

    if (num_of_args == 1) {
        snprintf(item_array.items[items_idx].key, sizeof(item_array.items[items_idx].key), "Rotate for account");
        item_array.items[items_idx].toString = items_rotateToDisplayString;
    } else {
        snprintf(item_array.items[items_idx].key, sizeof(item_array.items[items_idx].key), "Unknown Capability %d", *unknown_capabitilies);
        (*unknown_capabitilies)++;
        item_array.items[items_idx].toString = items_unknownCapabilityToDisplayString;
    }
}

static parser_error_t items_stdToDisplayString(uint16_t token_index, char *outVal, uint16_t *outValLen) {
    parsed_json_t json_all = parser_getParserTxObj()->tx_json.json;

    *outValLen = json_all.tokens[token_index].end - json_all.tokens[token_index].start + 1;
    snprintf(outVal, *outValLen, "%s", json_all.buffer + json_all.tokens[token_index].start);

    return parser_ok;
}

static parser_error_t items_nothingToDisplayString(__Z_UNUSED uint16_t token_index, char *outVal, uint16_t *outValLen) {
    *outValLen = 1;
    snprintf(outVal, *outValLen, " ");
    return parser_ok;
}

static parser_error_t items_warningToDisplayString(__Z_UNUSED uint16_t token_index, char *outVal, uint16_t *outValLen) {
    *outValLen = sizeof("UNSAFE TRANSACTION. This transaction's code was not recognized and does not limit capabilities for all signers. Signing this transaction may make arbitrary actions on the chain including loss of all funds.");
    snprintf(outVal, *outValLen, "UNSAFE TRANSACTION. This transaction's code was not recognized and does not limit capabilities for all signers. Signing this transaction may make arbitrary actions on the chain including loss of all funds.");
    return parser_ok;
}

static parser_error_t items_signingToDisplayString(__Z_UNUSED uint16_t token_index, char *outVal, uint16_t *outValLen) {
    *outValLen = sizeof("Transaction");
    snprintf(outVal, *outValLen, "Transaction");
    return parser_ok;
}

static parser_error_t items_requiringToDisplayString(__Z_UNUSED uint16_t token_index, char *outVal, uint16_t *outValLen) {
    *outValLen = sizeof("Capabilities");
    snprintf(outVal, *outValLen, "Capabilities");
    return parser_ok;
}

static parser_error_t items_transferToDisplayString(uint16_t token_index_json, char *outVal, uint16_t *outValLen) {
    char amount[50];
    uint8_t amount_len = 0;
    char to[65];
    uint8_t to_len = 0;
    char from[65];
    uint8_t from_len = 0;
    uint16_t token_index = 0;
    parsed_json_t json_all = parser_getParserTxObj()->tx_json.json;

    object_get_value(&json_all, token_index_json, "args", &token_index);

    array_get_nth_element(&json_all, token_index, 0, &token_index);
    strncpy(from, json_all.buffer + json_all.tokens[token_index].start, json_all.tokens[token_index].end - json_all.tokens[token_index].start);
    from_len = json_all.tokens[token_index].end - json_all.tokens[token_index].start;
    from[from_len] = '\0';

    array_get_nth_element(&json_all, token_index, 1, &token_index);
    strncpy(to, json_all.buffer + json_all.tokens[token_index].start, json_all.tokens[token_index].end - json_all.tokens[token_index].start);
    to_len = json_all.tokens[token_index].end - json_all.tokens[token_index].start;
    to[to_len] = '\0';

    array_get_nth_element(&json_all, token_index, 2, &token_index);
    strncpy(amount, json_all.buffer + json_all.tokens[token_index].start, json_all.tokens[token_index].end - json_all.tokens[token_index].start);
    amount_len = json_all.tokens[token_index].end - json_all.tokens[token_index].start;
    amount[amount_len] = '\0';

    *outValLen = amount_len + from_len + to_len + sizeof(" from ") + sizeof(" to ") + 4 * sizeof("\"");
    snprintf(outVal, *outValLen, "%s from \"%s\" to \"%s\"", amount, from, to);

    return parser_ok;
}

static parser_error_t items_rotateToDisplayString(uint16_t token_index_json, char *outVal, uint16_t *outValLen) {
    uint16_t token_index = 0;
    parsed_json_t json_all = parser_getParserTxObj()->tx_json.json;

    object_get_value(&json_all, token_index_json, "args", &token_index);
    array_get_nth_element(&json_all, token_index, 0, &token_index);

    *outValLen = json_all.tokens[token_index].end - json_all.tokens[token_index].start + sizeof("\"\"");
    snprintf(outVal, *outValLen, "\"%s\"", json_all.buffer + json_all.tokens[token_index].start);

    return parser_ok;
}

static parser_error_t items_gasToDisplayString(uint16_t token_index, char *outVal, uint16_t *outValLen) {
    char gasLimit[10];
    uint8_t gasLimit_len = 0;
    char gasPrice[64];
    uint8_t gasPrice_len = 0;
    parsed_json_t json_all = parser_getParserTxObj()->tx_json.json;
    uint16_t meta_token_index = token_index;

    parser_getJsonValue(&token_index, JSON_GAS_LIMIT);
    gasLimit_len = json_all.tokens[token_index].end - json_all.tokens[token_index].start + 1;
    snprintf(gasLimit, gasLimit_len, "%s", json_all.buffer + json_all.tokens[token_index].start);

    token_index = meta_token_index;
    parser_getJsonValue(&token_index, JSON_GAS_PRICE);
    gasPrice_len = json_all.tokens[token_index].end - json_all.tokens[token_index].start + 1;
    snprintf(gasPrice, gasPrice_len, "%s", json_all.buffer + json_all.tokens[token_index].start);

    *outValLen = gasLimit_len + gasPrice_len + sizeof("at most ") + sizeof(" at price ");
    snprintf(outVal, *outValLen, "at most %s at price %s", gasLimit, gasPrice);

    return parser_ok;
}

static parser_error_t items_hashToDisplayString(uint16_t token_index_json, char *outVal, uint16_t *outValLen) {
    *outValLen = sizeof(base64_hash);
    snprintf(outVal, *outValLen, "%s", base64_hash);
    return parser_ok;
}

static parser_error_t items_unknownCapabilityToDisplayString(uint16_t token_index_json, char *outVal, uint16_t *outValLen) {
    uint16_t token_index = 0;
    uint16_t args_count = 0;
    uint8_t len = 0;
    uint8_t outVal_idx= 0;
    parsed_json_t json_all = parser_getParserTxObj()->tx_json.json;

    object_get_value(&json_all, token_index_json, "name", &token_index);
    len = json_all.tokens[token_index].end - json_all.tokens[token_index].start + sizeof("name: ");
    snprintf(outVal, len, "name: %s", json_all.buffer + json_all.tokens[token_index].start);
    outVal_idx += len;

    // Remove null terminator
    outVal[outVal_idx - 1] = ',';
    
    // Add space
    outVal[outVal_idx] = ' ';
    outVal_idx++;

    object_get_value(&json_all, token_index_json, "args", &token_index);
    array_get_element_count(&json_all, token_index, &args_count);

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

    *outValLen = outVal_idx;

    return parser_ok;
}