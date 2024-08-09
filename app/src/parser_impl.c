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

#include "parser_impl.h"
#include "crypto_helper.h"
#include <base64.h>

static parser_error_t parser_getTransferValue(uint16_t* clist_array_idx, char **value, uint16_t *value_len);
static parser_error_t parser_getGasArgsFromClist(parsed_json_t *json_gas_args);
static parser_error_t parser_stdToDisplayString(char *inBuf, uint16_t inBufLen, char *outVal, uint16_t *outValLen);
static parser_error_t parser_transferToDisplayString(char *inBuf, uint16_t inBufLen, char *outVal, uint16_t *outValLen);
static parser_error_t parser_gasToDisplayString(char *inBuf, uint16_t inBufLen, char *outVal, uint16_t *outValLen);
static parser_error_t parser_unknownCapabilityToDisplayString(char *inBuf, uint16_t inBufLen, char *outVal, uint16_t *outValLen);

parser_tx_t parser_tx_obj;
parsed_json_t json_clist;
item_array_t item_array;

char signing_buf[] = "Transaction";
char capabilities_buf[] = "Capabilities";

uint8_t hash[BLAKE2B_HASH_SIZE] = {0};
uint8_t base64_hash[44];

parser_error_t _read_json_tx(parser_context_t *c, __Z_UNUSED parser_tx_t *v) {
    CHECK_ERROR(json_parse(&parser_tx_obj.tx_json.json, (const char *) c->buffer,
                           c->bufferLen));

    parser_tx_obj.tx_json.tx = (const char *) c->buffer;
    parser_tx_obj.tx_json.flags.cache_valid = 0;
    parser_tx_obj.tx_json.filter_msg_type_count = 0;
    parser_tx_obj.tx_json.filter_msg_from_count = 0;

    parser_initClistObject();

    return parser_ok;
}

parser_error_t parser_initItems() {
    MEMZERO(&item_array, sizeof(item_array_t));
    return parser_ok;
}

parser_error_t parser_storeItems(parser_context_t *ctx) {
    parsed_json_t json_gas_args;
    uint8_t items_idx = 0;
    uint8_t unknown_capabitilies = 1;

    strcpy(item_array.items[items_idx].key, "Signing");
    item_array.items[items_idx].buf = signing_buf;
    item_array.items[items_idx].len = sizeof(signing_buf);
    item_array.items[items_idx].toString = parser_stdToDisplayString;
    items_idx++;

    strcpy(item_array.items[items_idx].key, "On Network");
    parser_getJsonValueBuffer(parser_tx_obj.tx_json.json, "networkId", &(item_array.items[items_idx].buf), &(item_array.items[items_idx].len));
    item_array.items[items_idx].toString = parser_stdToDisplayString;
    items_idx++;

    strcpy(item_array.items[items_idx].key, "Requiring");
    item_array.items[items_idx].buf = capabilities_buf;
    item_array.items[items_idx].len = sizeof(capabilities_buf);
    item_array.items[items_idx].toString = parser_stdToDisplayString;
    items_idx++;

    strcpy(item_array.items[items_idx].key, "Of Key");
    parser_getJsonValueBuffer(parser_tx_obj.tx_json.json, "sender", &(item_array.items[items_idx].buf), &(item_array.items[items_idx].len));
    item_array.items[items_idx].toString = parser_stdToDisplayString;
    items_idx++;

    parser_getGasArgsFromClist(&json_gas_args);
    uint16_t args_count = 0;
    array_get_element_count(&json_gas_args, 0, &args_count);
    if (args_count == 0) {
        strcpy(item_array.items[items_idx].key, "Paying Gas");
        item_array.items[items_idx].buf = "";
        item_array.items[items_idx].len = 0;
        item_array.items[items_idx].toString = parser_stdToDisplayString;
    } else {
        snprintf(item_array.items[items_idx].key, strlen("Unknown Capability X") + 1, "Unknown Capability %d", unknown_capabitilies++);
        item_array.items[items_idx].buf = json_gas_args.buffer;
        item_array.items[items_idx].len = json_gas_args.bufferLen;
        item_array.items[items_idx].toString = parser_unknownCapabilityToDisplayString;
    }
    items_idx++;
    
    uint16_t obj_token_idx = 0;
    for (uint8_t i = 0; i < parser_getNumberOfTransfers(); i++, items_idx++) {
        snprintf(item_array.items[items_idx].key, sizeof(item_array.items[items_idx].key), "Transfer %d", i + 1);
        parser_getTransferValue(&obj_token_idx, &(item_array.items[items_idx].buf), &(item_array.items[items_idx].len));
        item_array.items[items_idx].toString = parser_transferToDisplayString;
    }

    strcpy(item_array.items[items_idx].key, "On Chain");
    parser_getJsonValueBuffer(parser_tx_obj.tx_json.json, "chainId", &(item_array.items[items_idx].buf), &(item_array.items[items_idx].len));
    item_array.items[items_idx].toString = parser_stdToDisplayString;
    items_idx++;

    strcpy(item_array.items[items_idx].key, "Using Gas");
    parser_getJsonValueBuffer(parser_tx_obj.tx_json.json, "gasLimit", &(item_array.items[items_idx].buf), &(item_array.items[items_idx].len));
    item_array.items[items_idx].toString = parser_gasToDisplayString;
    items_idx++;

    strcpy(item_array.items[items_idx].key, "Transaction Hash");
    if (blake2b_hash((uint8_t *)ctx->buffer, ctx->bufferLen, hash) != zxerr_ok) {
        return parser_unexpected_error;
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

    item_array.items[items_idx].buf = base64_hash;
    item_array.items[items_idx].buf[sizeof(base64_hash) - 1] = '\0';
    item_array.items[items_idx].len = sizeof(base64_hash);
    item_array.items[items_idx].toString = parser_stdToDisplayString;
    items_idx++;

    strcpy(item_array.items[items_idx].key, "Sign for Address");
    /*
    Currently launching cpp tests, so this is not available
    uint8_t address[32];
    uint16_t address_size;
    CHECK_ERROR(crypto_fillAddress(address, sizeof(address), &address_size));
    snprintf(outVal, address_size + 1, "%s", address);
    */
    item_array.items[items_idx].buf = "?";
    item_array.items[items_idx].len = 1;
    item_array.items[items_idx].toString = parser_stdToDisplayString;

    item_array.numOfItems = items_idx + 1;

    return parser_ok;
}

parser_error_t parser_getTotalItems(uint8_t *num_items) {
    *num_items = item_array.numOfItems;
    return parser_ok;
}

parser_error_t parser_getJsonValueBuffer(parsed_json_t json_obj, const char *key_name, char **outVal, uint16_t *outValLen) {
    uint16_t token_index = 0;

    // Search token_index to access the parsed JSON object
    object_get_value(&json_obj, 0, key_name, &token_index);

    *outValLen = (json_obj.tokens[token_index].end - json_obj.tokens[token_index].start);
    *outVal = json_obj.buffer + json_obj.tokens[token_index].start;

    return parser_ok;
}

parser_error_t parser_initClistObject() {
    uint16_t token_index = 0;

    CHECK_ERROR(object_get_value(&parser_tx_obj.tx_json.json, 0, "clist", &token_index));

    CHECK_ERROR(json_parse(&json_clist, parser_tx_obj.tx_json.json.buffer + parser_tx_obj.tx_json.json.tokens[token_index].start, parser_tx_obj.tx_json.json.tokens[token_index].end - parser_tx_obj.tx_json.json.tokens[token_index].start));

    return parser_ok;
}

parser_error_t parser_getNthClistObject(parsed_json_t *json_obj, uint8_t clist_array_idx) {
    uint16_t token_index = 0;
    
    CHECK_ERROR(array_get_nth_element(&json_clist, 0, clist_array_idx, &token_index));

    // Parse corresponding object in clist
    CHECK_ERROR(json_parse(json_obj, json_clist.buffer + json_clist.tokens[token_index].start, json_clist.tokens[token_index].end - json_clist.tokens[token_index].start));

    return parser_ok;
}

parser_error_t parser_isTransfer(parsed_json_t *json_obj) {
    uint16_t name_token_idx = 0;
    parser_error_t ret = parser_json_not_a_transfer;

    object_get_value(json_obj, 0, "name", &name_token_idx);

    if (((uint16_t) strlen("coin.TRANSFER")) == (json_obj->tokens[name_token_idx].end - json_obj->tokens[name_token_idx].start)) {
        if (MEMCMP("coin.TRANSFER",
            json_obj->buffer + json_obj->tokens[name_token_idx].start,
            json_obj->tokens[name_token_idx].end - json_obj->tokens[name_token_idx].start) == 0) {
            ret = parser_ok;
        }
    }

    return ret;
}

uint16_t parser_getNumberOfPossibleTransfers() {
    uint16_t number_of_transfers = 0;
    CHECK_ERROR(array_get_element_count(&json_clist, 0, &number_of_transfers));
    return number_of_transfers;
}

uint16_t parser_getNumberOfTransfers() {
    uint16_t number_of_transfers = 0;
    parsed_json_t json_obj;

    for (uint16_t i = 0; i < parser_getNumberOfPossibleTransfers(); i++) {
        parser_getNthClistObject(&json_obj, i);
        if (parser_isTransfer(&json_obj) == parser_ok) {
            number_of_transfers++;
        }
    }
    return number_of_transfers;
}

item_array_t *parser_getItemArray() {
    return &item_array;
}

static parser_error_t parser_getGasArgsFromClist(parsed_json_t *json_gas_args) {
    uint16_t name_token_idx = 0;
    parsed_json_t json_gas;
    parsed_json_t json_obj;
    uint16_t args_token_idx = 0;

    for (uint16_t i = 0; i < parser_getNumberOfPossibleTransfers(); i++) {
        parser_getNthClistObject(&json_obj, i);

        object_get_value(&json_obj, 0, "name", &name_token_idx);

        json_parse(&json_gas, json_obj.buffer, json_obj.tokens[name_token_idx].end - json_obj.tokens[name_token_idx].start);

        if (((uint16_t) strlen("coin.GAS")) == (json_obj.tokens[name_token_idx].end - json_obj.tokens[name_token_idx].start)) {
            if (MEMCMP("coin.GAS",
                json_obj.buffer + json_obj.tokens[name_token_idx].start,
                json_obj.tokens[name_token_idx].end - json_obj.tokens[name_token_idx].start) == 0) {

                object_get_value(&json_obj, 0, "args", &args_token_idx);
                json_parse(json_gas_args, json_obj.buffer + json_obj.tokens[args_token_idx].start, json_obj.tokens[args_token_idx].end - json_obj.tokens[args_token_idx].start);

                return parser_ok;
            }
        }
    }

    return parser_json_unexpected_error;
}

static parser_error_t parser_getTransferValue(uint16_t* clist_array_idx, char **value, uint16_t *value_len) {
    parsed_json_t json_obj;
    uint16_t token_index = 0;

    if (*clist_array_idx > parser_getNumberOfPossibleTransfers()) {
        return parser_value_out_of_range;
    }

    CHECK_ERROR(parser_getNthClistObject(&json_obj, *clist_array_idx));

    while (parser_isTransfer(&json_obj) == parser_json_not_a_transfer) {
        (*clist_array_idx)++;
        CHECK_ERROR(parser_getNthClistObject(&json_obj, *clist_array_idx));
    }

    (*clist_array_idx)++;

    object_get_value(&json_obj, 0, "args", &token_index);
    *value = json_obj.buffer + json_obj.tokens[token_index].start;
    *value_len = json_obj.tokens[token_index].end - json_obj.tokens[token_index].start;

    return parser_ok;
}

static parser_error_t parser_stdToDisplayString(char *inBuf, uint16_t inBufLen, char *outVal, uint16_t *outValLen) {
    snprintf(outVal, inBufLen + 1, "%s", inBuf);
    return parser_ok;
}

static parser_error_t parser_transferToDisplayString(char *inBuf, uint16_t inBufLen, char *outVal, uint16_t *outValLen) {
    char from[65];
    char to[65];
    char amount[10];
    uint8_t from_len = 0;
    uint8_t to_len = 0;
    uint8_t amount_len = 0;
    uint16_t buf_index = 0;
    uint16_t i = 0;

    // Reach first address in buffer
    while (inBuf[++buf_index] != '"') {
        ;
    }

    // From
    while (inBuf[++buf_index] != '"') {
        from[i++] = inBuf[buf_index];
    }
    from_len = i;
    from[from_len] = '\0';
    
    // Reach second address in buffer
    while (inBuf[++buf_index] != '"') {
        ;
    }

    i = 0;

    // To
    while (inBuf[++buf_index] != '"') {
        to[i++] = inBuf[buf_index];
    }
    to_len = i;
    to[to_len] = '\0';

    // Skip ","
    buf_index++;

    i = 0;

    while (inBuf[++buf_index] != ']') {
        amount[i++] = inBuf[buf_index];
    }
    amount_len = i;
    amount[amount_len] = '\0';

    *outValLen = amount_len + from_len + to_len + 15;
    snprintf(outVal, *outValLen, "%s from \"%s\" to \"%s\"", amount, from, to);

    return parser_ok;
}

static parser_error_t parser_gasToDisplayString(char *inBuf, uint16_t inBufLen, char *outVal, uint16_t *outValLen) {
    char gasLimit[10];
    char gasPrice[10];
    uint8_t gasLimit_len = 0;
    uint8_t gasPrice_len = 0;
    uint16_t buf_index = 0;
    uint16_t i = 0;

    // From
    while (inBuf[buf_index] != ',') {
        gasLimit[i++] = inBuf[buf_index];
        buf_index++;
    }
    gasLimit_len = i;
    gasLimit[gasLimit_len] = '\0';

    while (inBuf[++buf_index] != ':') {
        ;
    }

    while (inBuf[++buf_index] != ':') {
        ;
    }

    i = 0;

    while (inBuf[++buf_index] != ',') {
        gasPrice[i++] = inBuf[buf_index];
    }
    gasPrice_len = i;
    gasPrice[gasPrice_len] = '\0';

    *outValLen = gasPrice_len + gasLimit_len + 19;
    snprintf(outVal, *outValLen, "at most %s at price %s", gasLimit, gasPrice);

    return parser_ok;
}

static parser_error_t parser_unknownCapabilityToDisplayString(char *inBuf, uint16_t inBufLen, char *outVal, uint16_t *outValLen) {
    char name[20] = {0};
    char *arg;
    uint16_t name_len = 0;
    uint16_t buf_index = 1;
    uint16_t arg_len = 0;
    uint8_t arg_index = 1;
    uint16_t out_index = 0;

    while (!name_len) {
        while (inBuf[++buf_index] != 'n') {}
        if (MEMCMP("name", inBuf + buf_index, 4) == 0) {
            while (inBuf[++buf_index] != ':') {}
            // Skip "\""
            buf_index++;
            while (inBuf[++buf_index] != '"') {
                name[name_len++] = inBuf[buf_index];
            }
        }
    }

    snprintf(outVal, strlen("name: ,") + name_len + 1, "name: %s,", name);
    out_index += strlen("name: ,") + name_len;

    buf_index = 1;

    while (inBuf[buf_index - 1] != ']') {
        arg = inBuf + buf_index;
        arg_len = 0;
        while (inBuf[buf_index] != ',' && inBuf[buf_index] != ']') {
            buf_index++;
            arg_len++;
        }
        buf_index++;
        snprintf(outVal + out_index, strlen(" arg X: ,") + arg_len + 1, " arg %d: %s,", arg_index++, arg);
        out_index += strlen(" arg X: ,") + arg_len;
    }

    // Remove the last comma
    outVal[out_index - 1] = '\0';

    *outValLen = out_index;
    return parser_ok;
}


const char *parser_getErrorDescription(parser_error_t err) {
    switch (err) {
        case parser_ok:
            return "No error";
        case parser_no_data:
            return "No more data";
        case parser_init_context_empty:
            return "Initialized empty context";
        case parser_unexpected_buffer_end:
            return "Unexpected buffer end";
        case parser_unexpected_version:
            return "Unexpected version";
        case parser_unexpected_characters:
            return "Unexpected characters";
        case parser_unexpected_field:
            return "Unexpected field";
        case parser_duplicated_field:
            return "Unexpected duplicated field";
        case parser_value_out_of_range:
            return "Value out of range";
        case parser_unexpected_chain:
            return "Unexpected chain";
        case parser_missing_field:
            return "missing field";

        case parser_display_idx_out_of_range:
            return "display index out of range";
        case parser_display_page_out_of_range:
            return "display page out of range";
        case parser_tx_obj_empty:
            return "Tx obj empty";
        case parser_unexpected_value:
            return "Unexpected value";

        default:
            return "Unrecognized error code";
    }
}
