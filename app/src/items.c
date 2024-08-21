
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
#include "items_format.h"
#include "parser_impl.h"
#include <base64.h>

static items_error_t items_storeSigningTransaction();
static items_error_t items_storeNetwork();
static items_error_t items_storeRequiringCapabilities();
static items_error_t items_storeKey();
static items_error_t items_validateSigners();
static items_error_t items_storePayingGas();
static items_error_t items_storeAllTransfers();
static items_error_t items_storeCaution();
static items_error_t items_storeChainId();
static items_error_t items_storeUsingGas();
static items_error_t items_checkTxLengths();
static items_error_t items_storeHash();
static items_error_t items_storeSignForAddr();
static items_error_t items_storeGasItem(uint16_t json_token_index);
static items_error_t items_storeTxItem(parsed_json_t *json_all, uint16_t transfer_token_index, uint8_t *num_of_transfers);
static items_error_t items_storeTxCrossItem(parsed_json_t *json_all, uint16_t transfer_token_index,
                                            uint8_t *num_of_transfers);
static items_error_t items_storeTxRotateItem(parsed_json_t *json_all, uint16_t transfer_token_index);
static items_error_t items_storeUnknownItem(parsed_json_t *json_all, uint16_t transfer_token_index);

#define MAX_ITEM_LENGTH_TO_DISPLAY 256

item_array_t item_array;

uint8_t hash[BLAKE2B_HASH_SIZE] = {0};

char base64_hash[44];

void items_initItems() {
    MEMZERO(&item_array, sizeof(item_array_t));

    item_array.numOfUnknownCapabitilies = 1;

    for (uint8_t i = 0; i < sizeof(item_array.items) / sizeof(item_array.items[0]); i++) {
        item_array.items[i].can_display = bool_true;
    }
}

item_array_t *items_getItemArray() { return &item_array; }

void items_storeItems() {
    items_storeSigningTransaction();

    items_storeNetwork();

    items_storeRequiringCapabilities();

    items_storeKey();

    items_validateSigners();

    items_storePayingGas();

    items_storeAllTransfers();

    if (parser_validateMetaField() != parser_ok) {
        items_storeCaution();
    } else {
        items_storeChainId();

        items_storeUsingGas();
    }

    items_checkTxLengths();

    items_storeHash();

    items_storeSignForAddr();
}

uint16_t items_getTotalItems() { return item_array.numOfItems; }

static items_error_t items_storeSigningTransaction() {
    item_t *item = &item_array.items[item_array.numOfItems];

    strcpy(item->key, "Signing");
    item_array.toString[item_array.numOfItems] = items_signingToDisplayString;
    item_array.numOfItems++;

    return items_ok;
}

static items_error_t items_storeNetwork() {
    uint16_t *curr_token_idx = &item_array.items[item_array.numOfItems].json_token_index;
    item_t *item = &item_array.items[item_array.numOfItems];
    parsed_json_t *json_all = &(parser_getParserTxObj()->json);

    PARSER_TO_ITEMS_ERROR(object_get_value(json_all, *curr_token_idx, JSON_NETWORK_ID, curr_token_idx));

    if (!items_isNullField(*curr_token_idx)) {
        strcpy(item->key, "On Network");
        item_array.toString[item_array.numOfItems] = items_stdToDisplayString;
        item_array.numOfItems++;
    }

    return items_ok;
}

static items_error_t items_storeRequiringCapabilities() {
    item_t *item = &item_array.items[item_array.numOfItems];
    strcpy(item->key, "Requiring");
    item_array.toString[item_array.numOfItems] = items_requiringToDisplayString;
    item_array.numOfItems++;

    return items_ok;
}

static items_error_t items_storeKey() {
    parsed_json_t *json_all = &(parser_getParserTxObj()->json);
    uint16_t *curr_token_idx = &item_array.items[item_array.numOfItems].json_token_index;
    item_t *item = &item_array.items[item_array.numOfItems];

    PARSER_TO_ITEMS_ERROR(object_get_value(json_all, *curr_token_idx, JSON_SIGNERS, curr_token_idx));

    if (!items_isNullField(*curr_token_idx)) {
        PARSER_TO_ITEMS_ERROR(array_get_nth_element(json_all, *curr_token_idx, 0, curr_token_idx));
        PARSER_TO_ITEMS_ERROR(object_get_value(json_all, *curr_token_idx, JSON_PUBKEY, curr_token_idx));
        if (!items_isNullField(*curr_token_idx)) {
            strcpy(item->key, "Of Key");
            item_array.toString[item_array.numOfItems] = items_stdToDisplayString;
            item_array.numOfItems++;
        }
    }

    return items_ok;
}

static items_error_t items_validateSigners() {
    parsed_json_t *json_all = &(parser_getParserTxObj()->json);
    uint16_t *curr_token_idx = &item_array.items[item_array.numOfItems].json_token_index;
    item_t *item = &item_array.items[item_array.numOfItems];
    item_t *ofKey_item = &item_array.items[item_array.numOfItems - 1];
    uint16_t token_index = 0;

    PARSER_TO_ITEMS_ERROR(object_get_value(json_all, *curr_token_idx, JSON_SIGNERS, curr_token_idx));

    if (!items_isNullField(*curr_token_idx)) {
        array_get_nth_element(json_all, *curr_token_idx, 0, curr_token_idx);
        if (object_get_value(json_all, *curr_token_idx, JSON_CLIST, curr_token_idx) == parser_ok) {
            if (!items_isNullField(*curr_token_idx)) {
                uint16_t clist_token_index = *curr_token_idx;
                uint16_t clist_element_count = 0;
                PARSER_TO_ITEMS_ERROR(array_get_element_count(json_all, clist_token_index, &clist_element_count));

                for (uint8_t i = 0; i < clist_element_count; i++) {
                    if (array_get_nth_element(json_all, clist_token_index, i, &token_index) == parser_ok) {
                        uint16_t name_token_index = 0;
                        if (object_get_value(json_all, token_index, JSON_NAME, &name_token_index) == parser_ok) {
                            if (MEMCMP("coin.TRANSFER", json_all->buffer + json_all->tokens[name_token_index].start,
                                       sizeof("coin.TRANSFER") - 1) == 0) {
                                if (parser_findPubKeyInClist(ofKey_item->json_token_index) == parser_ok) {
                                    *curr_token_idx = 0;
                                    return items_ok;
                                }
                                break;
                            }
                        }
                    }
                }
                *curr_token_idx = 0;
                return items_ok;
            }
        }
    }

    strcpy(item->key, "Unscoped Signer");
    *curr_token_idx = ofKey_item->json_token_index;
    item_array.toString[item_array.numOfItems] = items_stdToDisplayString;
    item_array.numOfItems++;

    return items_ok;
}

static items_error_t items_storePayingGas() {
    parsed_json_t *json_all = &(parser_getParserTxObj()->json);
    uint16_t *curr_token_idx = &item_array.items[item_array.numOfItems].json_token_index;
    uint16_t token_index = 0;
    uint16_t name_token_index = 0;
    jsmntok_t *token;

    PARSER_TO_ITEMS_ERROR(object_get_value(json_all, *curr_token_idx, JSON_SIGNERS, curr_token_idx));

    if (!items_isNullField(*curr_token_idx)) {
        PARSER_TO_ITEMS_ERROR(array_get_nth_element(json_all, *curr_token_idx, 0, curr_token_idx));
        PARSER_TO_ITEMS_ERROR(object_get_value(json_all, *curr_token_idx, JSON_CLIST, curr_token_idx));

        if (!items_isNullField(*curr_token_idx)) {
            uint16_t clist_element_count = 0;
            PARSER_TO_ITEMS_ERROR(array_get_element_count(json_all, *curr_token_idx, &clist_element_count));

            for (uint16_t i = 0; i < clist_element_count; i++) {
                PARSER_TO_ITEMS_ERROR(array_get_nth_element(json_all, *curr_token_idx, i, &token_index));

                PARSER_TO_ITEMS_ERROR(object_get_value(json_all, token_index, JSON_NAME, &name_token_index));
                token = &(json_all->tokens[name_token_index]);

                if (MEMCMP("coin.GAS", json_all->buffer + token->start, token->end - token->start) == 0) {
                    *curr_token_idx = token_index;
                    items_storeGasItem(*curr_token_idx);
                    item_array.numOfItems++;
                    return items_ok;
                }
            }
        }
    }

    *curr_token_idx = 0;
    return items_ok;
}

static items_error_t items_storeAllTransfers() {
    parsed_json_t *json_all = &(parser_getParserTxObj()->json);
    uint16_t *curr_token_idx = &item_array.items[item_array.numOfItems].json_token_index;
    uint16_t token_index = 0;
    uint8_t num_of_transfers = 1;
    jsmntok_t *token;
    item_t *item = &item_array.items[item_array.numOfItems];

    PARSER_TO_ITEMS_ERROR(object_get_value(json_all, 0, JSON_SIGNERS, curr_token_idx));

    if (!items_isNullField(*curr_token_idx)) {
        array_get_nth_element(json_all, *curr_token_idx, 0, curr_token_idx);

        if (object_get_value(json_all, *curr_token_idx, JSON_CLIST, curr_token_idx) == parser_ok) {
            if (!items_isNullField(*curr_token_idx)) {
                uint16_t clist_token_index = *curr_token_idx;
                uint16_t clist_element_count = 0;

                array_get_element_count(json_all, clist_token_index, &clist_element_count);

                for (uint8_t i = 0; i < clist_element_count; i++) {
                    if (array_get_nth_element(json_all, clist_token_index, i, &token_index) == parser_ok) {
                        uint16_t name_token_index = 0;
                        if (object_get_value(json_all, token_index, JSON_NAME, &name_token_index) == parser_ok) {
                            token = &(json_all->tokens[name_token_index]);
                            if (MEMCMP("coin.TRANSFER_XCHAIN", json_all->buffer + token->start,
                                       sizeof("coin.TRANSFER_XCHAIN") - 1) == 0) {
                                *curr_token_idx = token_index;
                                items_storeTxCrossItem(json_all, token_index, &num_of_transfers);
                                item_array.numOfItems++;
                            } else if (MEMCMP("coin.TRANSFER", json_all->buffer + token->start,
                                              sizeof("coin.TRANSFER") - 1) == 0) {
                                *curr_token_idx = token_index;
                                items_storeTxItem(json_all, token_index, &num_of_transfers);
                                item_array.numOfItems++;
                            } else if (MEMCMP("coin.ROTATE", json_all->buffer + token->start, sizeof("coin.ROTATE") - 1) ==
                                       0) {
                                *curr_token_idx = token_index;
                                items_storeTxRotateItem(json_all, token_index);
                                item_array.numOfItems++;
                            } else if (MEMCMP("coin.GAS", json_all->buffer + token->start, sizeof("coin.GAS") - 1) != 0) {
                                // Any other case that's not coin.GAS
                                *curr_token_idx = token_index;
                                items_storeUnknownItem(json_all, token_index);
                                item_array.toString[item_array.numOfItems] = items_unknownCapabilityToDisplayString;
                                item_array.numOfItems++;
                            }
                            curr_token_idx = &item_array.items[item_array.numOfItems].json_token_index;
                            item = &item_array.items[item_array.numOfItems];
                        }
                    }
                }
                return items_ok;
            }
        }
    }

    // Non-existing/Null Signers or Clist
    strcpy(item->key, "WARNING");
    item_array.toString[item_array.numOfItems] = items_warningToDisplayString;
    item_array.numOfItems++;
    *curr_token_idx = 0;

    return items_ok;
}

static items_error_t items_storeCaution() {
    item_t *item = &item_array.items[item_array.numOfItems];

    strcpy(item->key, "CAUTION");
    item_array.toString[item_array.numOfItems] = items_cautionToDisplayString;
    item_array.numOfItems++;

    return items_ok;
}

static items_error_t items_storeChainId() {
    uint16_t *curr_token_idx = &item_array.items[item_array.numOfItems].json_token_index;
    item_t *item = &item_array.items[item_array.numOfItems];
    parsed_json_t *json_all = &(parser_getParserTxObj()->json);

    PARSER_TO_ITEMS_ERROR(object_get_value(json_all, 0, JSON_META, curr_token_idx));

    if (!items_isNullField(*curr_token_idx)) {
        PARSER_TO_ITEMS_ERROR(object_get_value(json_all, *curr_token_idx, JSON_CHAIN_ID, curr_token_idx));
        if (!items_isNullField(*curr_token_idx)) {
            strcpy(item->key, "On Chain");
            item_array.toString[item_array.numOfItems] = items_stdToDisplayString;
            item_array.numOfItems++;
        }
    }

    return items_ok;
}

static items_error_t items_storeUsingGas() {
    uint16_t *curr_token_idx = &item_array.items[item_array.numOfItems].json_token_index;
    item_t *item = &item_array.items[item_array.numOfItems];
    parsed_json_t *json_all = &(parser_getParserTxObj()->json);

    PARSER_TO_ITEMS_ERROR(object_get_value(json_all, 0, JSON_META, curr_token_idx));

    if (!items_isNullField(*curr_token_idx)) {
        strcpy(item->key, "Using Gas");
        item_array.toString[item_array.numOfItems] = items_gasToDisplayString;
        item_array.numOfItems++;
    } else {
        *curr_token_idx = 0;
    }

    return items_ok;
}

static items_error_t items_checkTxLengths() {
    item_t *item = &item_array.items[item_array.numOfItems];

    for (uint8_t i = 0; i < item_array.numOfItems; i++) {
        if (!item_array.items[i].can_display) {
            strcpy(item->key, "WARNING");
            item_array.toString[item_array.numOfItems] = items_txTooLargeToDisplayString;
            item_array.numOfItems++;
            return items_ok;
        }
    }

    return items_ok;
}

static items_error_t items_storeHash() {
    item_t *item = &item_array.items[item_array.numOfItems];

    strcpy(item->key, "Transaction hash");

    if (blake2b_hash((uint8_t *)parser_getParserTxObj()->json.buffer, parser_getParserTxObj()->json.bufferLen, hash) !=
        zxerr_ok) {
        return items_error;
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

    item_array.toString[item_array.numOfItems] = items_hashToDisplayString;
    item_array.numOfItems++;

    return items_ok;
}

static items_error_t items_storeSignForAddr() {
#if defined(TARGET_NANOS) || defined(TARGET_NANOX) || defined(TARGET_NANOS2) || defined(TARGET_STAX) || defined(TARGET_FLEX)
    item_t *item = &item_array.items[item_array.numOfItems];

    strcpy(item->key, "Sign for Address");
    item_array.toString[item_array.numOfItems] = items_signForAddrToDisplayString;
    item_array.numOfItems++;
#endif
    return items_ok;
}

static items_error_t items_storeGasItem(uint16_t json_token_index) {
    uint16_t token_index = 0;
    uint16_t args_count = 0;
    parsed_json_t *json_all = &(parser_getParserTxObj()->json);
    item_t *item = &item_array.items[item_array.numOfItems];

    PARSER_TO_ITEMS_ERROR(object_get_value(json_all, json_token_index, "args", &token_index));
    PARSER_TO_ITEMS_ERROR(array_get_element_count(json_all, token_index, &args_count));

    if (args_count > 0) {
        snprintf(item->key, sizeof(item->key), "Unknown Capability %d", item_array.numOfUnknownCapabitilies);
        item_array.numOfUnknownCapabitilies++;
        item_array.toString[item_array.numOfItems] = items_unknownCapabilityToDisplayString;
    } else {
        strcpy(item->key, "Paying Gas");
        item_array.toString[item_array.numOfItems] = items_nothingToDisplayString;
    }

    return items_ok;
}

static items_error_t items_storeTxItem(parsed_json_t *json_all, uint16_t transfer_token_index, uint8_t *num_of_transfers) {
    uint16_t token_index = 0;
    uint16_t num_of_args = 0;
    item_t *item = &item_array.items[item_array.numOfItems];

    PARSER_TO_ITEMS_ERROR(object_get_value(json_all, transfer_token_index, "args", &token_index));

    PARSER_TO_ITEMS_ERROR(array_get_element_count(json_all, token_index, &num_of_args));

    if (num_of_args == 3) {
        snprintf(item->key, sizeof(item->key), "Transfer %d", *num_of_transfers);
        (*num_of_transfers)++;
        item_array.toString[item_array.numOfItems] = items_transferToDisplayString;
    } else {
        snprintf(item->key, sizeof(item->key), "Unknown Capability %d", item_array.numOfUnknownCapabitilies);
        item_array.numOfUnknownCapabitilies++;
        item_array.toString[item_array.numOfItems] = items_unknownCapabilityToDisplayString;

        if (num_of_args > 5 ||
            json_all->tokens[token_index].end - json_all->tokens[token_index].start > MAX_ITEM_LENGTH_TO_DISPLAY) {
            item->can_display = bool_false;
        }
    }

    return items_ok;
}

static items_error_t items_storeTxCrossItem(parsed_json_t *json_all, uint16_t transfer_token_index,
                                            uint8_t *num_of_transfers) {
    uint16_t token_index = 0;
    uint16_t num_of_args = 0;
    item_t *item = &item_array.items[item_array.numOfItems];

    PARSER_TO_ITEMS_ERROR(object_get_value(json_all, transfer_token_index, "args", &token_index));

    PARSER_TO_ITEMS_ERROR(array_get_element_count(json_all, token_index, &num_of_args));

    if (num_of_args == 4) {
        snprintf(item->key, sizeof(item->key), "Transfer %d", *num_of_transfers);
        (*num_of_transfers)++;
        item_array.toString[item_array.numOfItems] = items_crossTransferToDisplayString;
    } else {
        snprintf(item->key, sizeof(item->key), "Unknown Capability %d", item_array.numOfUnknownCapabitilies);
        item_array.numOfUnknownCapabitilies++;
        item_array.toString[item_array.numOfItems] = items_unknownCapabilityToDisplayString;

        if (num_of_args > 5 ||
            json_all->tokens[token_index].end - json_all->tokens[token_index].start > MAX_ITEM_LENGTH_TO_DISPLAY) {
            item->can_display = bool_false;
        }
    }

    return items_ok;
}

static items_error_t items_storeTxRotateItem(parsed_json_t *json_all, uint16_t transfer_token_index) {
    uint16_t token_index = 0;
    uint16_t num_of_args = 0;
    item_t *item = &item_array.items[item_array.numOfItems];

    PARSER_TO_ITEMS_ERROR(object_get_value(json_all, transfer_token_index, "args", &token_index));

    PARSER_TO_ITEMS_ERROR(array_get_element_count(json_all, token_index, &num_of_args));

    if (num_of_args == 1) {
        snprintf(item->key, sizeof(item->key), "Rotate for account");
        item_array.toString[item_array.numOfItems] = items_rotateToDisplayString;
    } else {
        snprintf(item->key, sizeof(item->key), "Unknown Capability %d", item_array.numOfUnknownCapabitilies);
        item_array.numOfUnknownCapabitilies++;
        item_array.toString[item_array.numOfItems] = items_unknownCapabilityToDisplayString;

        if (num_of_args > 5 ||
            json_all->tokens[token_index].end - json_all->tokens[token_index].start > MAX_ITEM_LENGTH_TO_DISPLAY) {
            item->can_display = bool_false;
        }
    }

    return items_ok;
}

static items_error_t items_storeUnknownItem(parsed_json_t *json_all, uint16_t transfer_token_index) {
    uint16_t token_index = 0;
    uint16_t num_of_args = 0;
    item_t *item = &item_array.items[item_array.numOfItems];

    PARSER_TO_ITEMS_ERROR(object_get_value(json_all, transfer_token_index, "args", &token_index));

    PARSER_TO_ITEMS_ERROR(array_get_element_count(json_all, token_index, &num_of_args));

    snprintf(item->key, sizeof(item->key), "Unknown Capability %d", item_array.numOfUnknownCapabitilies);
    item_array.numOfUnknownCapabitilies++;
    item_array.toString[item_array.numOfItems] = items_unknownCapabilityToDisplayString;

    if (num_of_args > 5 ||
        json_all->tokens[token_index].end - json_all->tokens[token_index].start > MAX_ITEM_LENGTH_TO_DISPLAY) {
        item->can_display = bool_false;
    }

    return items_ok;
}
