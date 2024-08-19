
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

static items_error_t items_storeSigningTransaction(uint8_t *items_idx);
static items_error_t items_storeNetwork(uint8_t *items_idx);
static items_error_t items_storeRequiringCapabilities(uint8_t *items_idx);
static items_error_t items_storeKey(uint8_t *items_idx);
static items_error_t items_validateSigners(uint8_t *items_idx);
static items_error_t items_storePayingGas(uint8_t *items_idx, uint8_t *unknown_capabitilies);
static items_error_t items_storeAllTransfers(uint8_t *items_idx, uint8_t *unknown_capabitilies);
static items_error_t items_storeCaution(uint8_t *items_idx);
static items_error_t items_storeChainId(uint8_t *items_idx);
static items_error_t items_storeUsingGas(uint8_t *items_idx);
static items_error_t items_checkTxLengths(uint8_t *items_idx);
static items_error_t items_storeHash(uint8_t *items_idx);
static items_error_t items_storeSignForAddr(uint8_t *items_idx);
static items_error_t items_storeGasItem(uint16_t json_token_index, uint8_t items_idx, uint8_t *unknown_capabitilies);
static items_error_t items_storeTransferItem(parsed_json_t *json_all, uint16_t transfer_token_index, uint8_t items_idx, uint8_t *num_of_transfers, uint8_t *unknown_capabitilies);
static items_error_t items_storeCrossTransferItem(parsed_json_t *json_all, uint16_t transfer_token_index, uint8_t items_idx, uint8_t *num_of_transfers, uint8_t *unknown_capabitilies);
static items_error_t items_storeRotateItem(parsed_json_t *json_all, uint16_t transfer_token_index, uint8_t items_idx, uint8_t *unknown_capabitilies);
static items_error_t items_storeUnknownItem(parsed_json_t *json_all, uint16_t transfer_token_index, uint8_t items_idx, uint8_t *unknown_capabitilies);

#define MAX_ITEM_LENGTH_TO_DISPLAY 1000 // TODO : Check other apps to find this number

item_array_t item_array = {0};

uint8_t hash[BLAKE2B_HASH_SIZE] = {0};
char base64_hash[44];

void items_initItems() {
    MEMZERO(&item_array, sizeof(item_array_t));

    for (uint8_t i = 0; i < sizeof(item_array.items) / sizeof(item_array.items[0]); i++) {
        item_array.items[i].can_display = bool_true;
    }
}

item_array_t *items_getItemArray() {
    return &item_array;
}

void items_storeItems() {
    uint8_t items_idx = 0;
    uint8_t unknown_capabitilies = 1;

    items_storeSigningTransaction(&items_idx);

    items_storeNetwork(&items_idx);

    items_storeRequiringCapabilities(&items_idx);

    items_storeKey(&items_idx);

    items_validateSigners(&items_idx);

    items_storePayingGas(&items_idx, &unknown_capabitilies);

    items_storeAllTransfers(&items_idx, &unknown_capabitilies);

    if (parser_validateMetaField() != parser_ok) {
        items_storeCaution(&items_idx);
    } else {
        items_storeChainId(&items_idx);

        items_storeUsingGas(&items_idx);
    }

    items_checkTxLengths(&items_idx);

    items_storeHash(&items_idx);

    items_storeSignForAddr(&items_idx);

    item_array.numOfItems = items_idx;
}

uint16_t items_getTotalItems() {
    return item_array.numOfItems;
}

static items_error_t items_storeSigningTransaction(uint8_t *items_idx) {
    strcpy(item_array.items[*items_idx].key, "Signing");
    item_array.toString[*items_idx] = items_signingToDisplayString;
    (*items_idx)++;

    return items_ok;
}

static items_error_t items_storeNetwork(uint8_t *items_idx) {
    uint16_t *curr_token_idx = &item_array.items[*items_idx].json_token_index;

    if (parser_getJsonValue(curr_token_idx, JSON_NETWORK_ID) == parser_ok) {
        strcpy(item_array.items[*items_idx].key, "On Network");
        item_array.toString[*items_idx] = items_stdToDisplayString;
        (*items_idx)++;
    }

    return items_ok;
}

static items_error_t items_storeRequiringCapabilities(uint8_t *items_idx) {
    strcpy(item_array.items[*items_idx].key, "Requiring");
    item_array.toString[*items_idx] = items_requiringToDisplayString;
    (*items_idx)++;

    return items_ok;
}

static items_error_t items_storeKey(uint8_t *items_idx) {
    parsed_json_t *json_all = &(parser_getParserTxObj()->tx_json.json);
    uint16_t *curr_token_idx = &item_array.items[*items_idx].json_token_index;

    if (parser_getJsonValue(curr_token_idx, JSON_SIGNERS) == parser_ok) {
        array_get_nth_element(json_all, *curr_token_idx, 0, curr_token_idx);
        if (parser_getJsonValue(curr_token_idx, JSON_PUBKEY) == parser_ok) {
            strcpy(item_array.items[*items_idx].key, "Of Key");
            item_array.toString[*items_idx] = items_stdToDisplayString;
            (*items_idx)++;
        }
    }

    return items_ok;
}

static items_error_t items_validateSigners(uint8_t *items_idx) {
    parsed_json_t *json_all = &(parser_getParserTxObj()->tx_json.json);
    uint16_t *curr_token_idx = &item_array.items[*items_idx].json_token_index;
    uint16_t token_index = 0;

    if (parser_getJsonValue(curr_token_idx, JSON_SIGNERS) == parser_ok) {
        array_get_nth_element(json_all, *curr_token_idx, 0, curr_token_idx);
        if (parser_getJsonValue(curr_token_idx, JSON_CLIST) == parser_ok) {
            uint16_t clist_token_index = *curr_token_idx;

            for (uint8_t i = 0; i < parser_getNumberOfClistElements(); i++) {
                if (array_get_nth_element(json_all, clist_token_index, i, &token_index) == parser_ok) {
                    uint16_t name_token_index = 0;
                    if (object_get_value(json_all, token_index, JSON_NAME, &name_token_index) == parser_ok) {
                        if (MEMCMP("coin.TRANSFER", json_all->buffer + json_all->tokens[name_token_index].start,
                                sizeof("coin.TRANSFER") - 1) == 0) {
                            if (parser_findPubKeyInClist(item_array.items[*items_idx - 1].json_token_index) == parser_ok) {
                                item_array.items[*items_idx].json_token_index = 0;
                                return items_ok;
                            }
                            break;
                        }
                    }
                }
            }
            item_array.items[*items_idx].json_token_index = 0;
            return items_ok;
        }
    }

    strcpy(item_array.items[*items_idx].key, "Unscoped Signer");
    *curr_token_idx = item_array.items[*items_idx - 1].json_token_index;
    item_array.toString[*items_idx] = items_stdToDisplayString;
    (*items_idx)++;

    return items_ok;
}

static items_error_t items_storePayingGas(uint8_t *items_idx, uint8_t *unknown_capabitilies) {
    parsed_json_t *json_all = &(parser_getParserTxObj()->tx_json.json);
    uint16_t *curr_token_idx = &item_array.items[*items_idx].json_token_index;

    if (parser_getJsonValue(curr_token_idx, JSON_SIGNERS) == parser_ok) {
        array_get_nth_element(json_all, *curr_token_idx, 0, curr_token_idx);
        if (parser_getJsonValue(curr_token_idx, JSON_CLIST) == parser_ok) {
            parser_getGasObject(curr_token_idx);
            items_storeGasItem(*curr_token_idx, *items_idx, unknown_capabitilies);
            (*items_idx)++;
        } else {
            *curr_token_idx = 0;
        }
    }

    return items_ok;
}

static items_error_t items_storeAllTransfers(uint8_t *items_idx, uint8_t *unknown_capabitilies) {
    parsed_json_t *json_all = &(parser_getParserTxObj()->tx_json.json);
    uint16_t *curr_token_idx = &item_array.items[*items_idx].json_token_index;
    uint16_t token_index = 0;
    uint8_t num_of_transfers = 1;

    if (parser_getJsonValue(curr_token_idx, JSON_SIGNERS) == parser_ok) {
        array_get_nth_element(json_all, *curr_token_idx, 0, curr_token_idx);
        if (parser_getJsonValue(curr_token_idx, JSON_CLIST) == parser_ok) {
            uint16_t clist_token_index = *curr_token_idx;
            for (uint8_t i = 0; i < parser_getNumberOfClistElements(); i++) {
                if (array_get_nth_element(json_all, clist_token_index, i, &token_index) == parser_ok) {
                    uint16_t name_token_index = 0;
                    if (object_get_value(json_all, token_index, JSON_NAME, &name_token_index) == parser_ok) {
                        if (MEMCMP("coin.TRANSFER_XCHAIN", json_all->buffer + json_all->tokens[name_token_index].start,
                                sizeof("coin.TRANSFER_XCHAIN") - 1) == 0) {
                            *curr_token_idx = token_index;
                            items_storeCrossTransferItem(json_all, token_index, *items_idx, &num_of_transfers, unknown_capabitilies);
                            (*items_idx)++;
                        } else if (MEMCMP("coin.TRANSFER", json_all->buffer + json_all->tokens[name_token_index].start,
                                sizeof("coin.TRANSFER") - 1) == 0) {
                            *curr_token_idx = token_index;
                            items_storeTransferItem(json_all, token_index, *items_idx, &num_of_transfers, unknown_capabitilies);
                            (*items_idx)++;
                        } else if (MEMCMP("coin.ROTATE", json_all->buffer + json_all->tokens[name_token_index].start,
                                sizeof("coin.ROTATE") - 1) == 0) {
                            *curr_token_idx = token_index;
                            items_storeRotateItem(json_all, token_index, *items_idx, unknown_capabitilies);
                            (*items_idx)++;
                        } else if (MEMCMP("coin.GAS", json_all->buffer + json_all->tokens[name_token_index].start,
                                sizeof("coin.GAS") - 1) != 0) {
                            // Any other case that's not coin.GAS
                            *curr_token_idx = token_index;
                            items_storeUnknownItem(json_all, token_index, *items_idx, unknown_capabitilies);
                            item_array.toString[*items_idx] = items_unknownCapabilityToDisplayString;
                            (*items_idx)++;
                        }
                        curr_token_idx = &item_array.items[*items_idx].json_token_index;
                    }
                }
            }
        } else {
            // No Clist given, Raise warning
            strcpy(item_array.items[*items_idx].key, "WARNING");
            item_array.toString[*items_idx] = items_warningToDisplayString;
            (*items_idx)++;
        }
    }

    *curr_token_idx = 0;

    return items_ok;
}

static items_error_t items_storeCaution(uint8_t *items_idx) {
    strcpy(item_array.items[*items_idx].key, "CAUTION");
    item_array.toString[*items_idx] = items_cautionToDisplayString;
    (*items_idx)++;
    return items_ok;
}

static items_error_t items_storeChainId(uint8_t *items_idx) {
    uint16_t *curr_token_idx = &item_array.items[*items_idx].json_token_index;

    if (parser_getJsonValue(curr_token_idx, JSON_META) == parser_ok) {
        if (parser_getJsonValue(curr_token_idx, JSON_CHAIN_ID) == parser_ok) {
            strcpy(item_array.items[*items_idx].key, "On Chain");
            item_array.toString[*items_idx] = items_stdToDisplayString;
            (*items_idx)++;
        }
    }
    return items_ok;
}

static items_error_t items_storeUsingGas(uint8_t *items_idx) {
    uint16_t *curr_token_idx = &item_array.items[*items_idx].json_token_index;

    if (parser_getJsonValue(curr_token_idx, JSON_META) == parser_ok) {
        strcpy(item_array.items[*items_idx].key, "Using Gas");
        item_array.toString[*items_idx] = items_gasToDisplayString;
        (*items_idx)++;
    } else {
        *curr_token_idx = 0;
    }

    return items_ok;

}

static items_error_t items_checkTxLengths(uint8_t *items_idx) {
    for (uint8_t i = 0; i < *items_idx; i++) {
        if (!item_array.items[i].can_display) {
            strcpy(item_array.items[*items_idx].key, "WARNING");
            item_array.toString[*items_idx] = items_txTooLargeToDisplayString;
            (*items_idx)++;
            return items_ok;
        }
    }

    return items_ok;
}

static items_error_t items_storeHash(uint8_t *items_idx) {
    strcpy(item_array.items[*items_idx].key, "Transaction hash");

    if (blake2b_hash((uint8_t *)parser_getParserTxObj()->tx_json.json.buffer, parser_getParserTxObj()->tx_json.json.bufferLen, hash) != zxerr_ok) {
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

    item_array.toString[*items_idx] = items_hashToDisplayString;
    (*items_idx)++;

    return items_ok;
}

static items_error_t items_storeSignForAddr(uint8_t *items_idx) {
    strcpy(item_array.items[*items_idx].key, "Sign for Address");
    item_array.toString[*items_idx] = items_signForAddrToDisplayString;
    (*items_idx)++;

    return items_ok;
}

static items_error_t items_storeGasItem(uint16_t json_token_index, uint8_t items_idx, uint8_t *unknown_capabitilies) {
    uint16_t token_index = 0;
    uint16_t args_count = 0;
    parsed_json_t *json_all = &(parser_getParserTxObj()->tx_json.json);

    object_get_value(json_all, json_token_index, "args", &token_index);
    array_get_element_count(json_all, token_index, &args_count);

    if (args_count > 0) {
        snprintf(item_array.items[items_idx].key, sizeof(item_array.items[items_idx].key), "Unknown Capability %d", *unknown_capabitilies);
        (*unknown_capabitilies)++;
        item_array.toString[items_idx] = items_unknownCapabilityToDisplayString;
    } else {
        strcpy(item_array.items[items_idx].key, "Paying Gas");
        item_array.toString[items_idx] = items_nothingToDisplayString;
    }

    return items_ok;
}

static items_error_t items_storeTransferItem(parsed_json_t *json_all, uint16_t transfer_token_index, uint8_t items_idx, uint8_t *num_of_transfers, uint8_t *unknown_capabitilies) {
    uint16_t token_index = 0;
    uint16_t num_of_args = 0;

    object_get_value(json_all, transfer_token_index, "args", &token_index);

    array_get_element_count(json_all, token_index, &num_of_args);

    if (num_of_args == 3) {
        snprintf(item_array.items[items_idx].key, sizeof(item_array.items[items_idx].key), "Transfer %d", *num_of_transfers);
        (*num_of_transfers)++;
        item_array.toString[items_idx] = items_transferToDisplayString;
    } else {
        snprintf(item_array.items[items_idx].key, sizeof(item_array.items[items_idx].key), "Unknown Capability %d", *unknown_capabitilies);
        (*unknown_capabitilies)++;
        item_array.toString[items_idx] = items_unknownCapabilityToDisplayString;

        if (num_of_args > 5 || json_all->tokens[token_index].end - json_all->tokens[token_index].start > MAX_ITEM_LENGTH_TO_DISPLAY) {
            item_array.items[items_idx].can_display = bool_false;
        }
    }

    return items_ok;
}

static items_error_t items_storeCrossTransferItem(parsed_json_t *json_all, uint16_t transfer_token_index, uint8_t items_idx, uint8_t *num_of_transfers, uint8_t *unknown_capabitilies) {
    uint16_t token_index = 0;
    uint16_t num_of_args = 0;

    object_get_value(json_all, transfer_token_index, "args", &token_index);

    array_get_element_count(json_all, token_index, &num_of_args);

    if (num_of_args == 4) {
        snprintf(item_array.items[items_idx].key, sizeof(item_array.items[items_idx].key), "Transfer %d", *num_of_transfers);
        (*num_of_transfers)++;
        item_array.toString[items_idx] = items_crossTransferToDisplayString;
    } else {
        snprintf(item_array.items[items_idx].key, sizeof(item_array.items[items_idx].key), "Unknown Capability %d", *unknown_capabitilies);
        (*unknown_capabitilies)++;
        item_array.toString[items_idx] = items_unknownCapabilityToDisplayString;

        if (num_of_args > 5 || json_all->tokens[token_index].end - json_all->tokens[token_index].start > MAX_ITEM_LENGTH_TO_DISPLAY) {
            item_array.items[items_idx].can_display = bool_false;
        }
    }

    return items_ok;
}

static items_error_t items_storeRotateItem(parsed_json_t *json_all, uint16_t transfer_token_index, uint8_t items_idx, uint8_t *unknown_capabitilies) {
    uint16_t token_index = 0;
    uint16_t num_of_args = 0;

    object_get_value(json_all, transfer_token_index, "args", &token_index);

    array_get_element_count(json_all, token_index, &num_of_args);

    if (num_of_args == 1) {
        snprintf(item_array.items[items_idx].key, sizeof(item_array.items[items_idx].key), "Rotate for account");
        item_array.toString[items_idx] = items_rotateToDisplayString;
    } else {
        snprintf(item_array.items[items_idx].key, sizeof(item_array.items[items_idx].key), "Unknown Capability %d", *unknown_capabitilies);
        (*unknown_capabitilies)++;
        item_array.toString[items_idx] = items_unknownCapabilityToDisplayString;

        if (num_of_args > 5 || json_all->tokens[token_index].end - json_all->tokens[token_index].start > MAX_ITEM_LENGTH_TO_DISPLAY) {
            item_array.items[items_idx].can_display = bool_false;
        }
    }

    return items_ok;
}

static items_error_t items_storeUnknownItem(parsed_json_t *json_all, uint16_t transfer_token_index, uint8_t items_idx, uint8_t *unknown_capabitilies) {
    uint16_t token_index = 0;
    uint16_t num_of_args = 0;

    object_get_value(json_all, transfer_token_index, "args", &token_index);

    array_get_element_count(json_all, token_index, &num_of_args);

    snprintf(item_array.items[items_idx].key, sizeof(item_array.items[items_idx].key), "Unknown Capability %d", *unknown_capabitilies);
    (*unknown_capabitilies)++;
    item_array.toString[items_idx] = items_unknownCapabilityToDisplayString;

    if (num_of_args > 5 || json_all->tokens[token_index].end - json_all->tokens[token_index].start > MAX_ITEM_LENGTH_TO_DISPLAY) {
        item_array.items[items_idx].can_display = bool_false;
    }

    return items_ok;
}