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


parser_tx_t parser_tx_obj;

parser_error_t _read_json_tx(parser_context_t *c, __Z_UNUSED parser_tx_t *v) {
    CHECK_ERROR(json_parse(&parser_tx_obj.tx_json.json, (const char *) c->buffer,
                           c->bufferLen));

    parser_tx_obj.tx_json.tx = (const char *) c->buffer;
    parser_tx_obj.tx_json.flags.cache_valid = 0;
    parser_tx_obj.tx_json.filter_msg_type_count = 0;
    parser_tx_obj.tx_json.filter_msg_from_count = 0;

    return parser_ok;
}

parser_tx_t *parser_getParserTxObj() {
    return &parser_tx_obj;
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

uint16_t parser_getNumberOfClistElements() {
    uint16_t number_of_elements = 0;
    parsed_json_t *json_all = &parser_tx_obj.tx_json.json;
    uint16_t token_index = 0;

    parser_getJsonValue(&token_index, JSON_SIGNERS);
    array_get_nth_element(&json_all, token_index, 0, &token_index);
    parser_getJsonValue(&token_index, JSON_CLIST);

    CHECK_ERROR(array_get_element_count(json_all, token_index, &number_of_elements));

    return number_of_elements;
}

parser_error_t parser_getJsonValue(uint16_t *json_token_index, const char *key) {
    parsed_json_t json_obj;
    uint16_t token_index = 0;

    object_get_value(&parser_tx_obj.tx_json.json, *json_token_index, key, &token_index);

    json_parse(&json_obj, parser_tx_obj.tx_json.json.buffer + parser_tx_obj.tx_json.json.tokens[token_index].start, parser_tx_obj.tx_json.json.tokens[token_index].end - parser_tx_obj.tx_json.json.tokens[token_index].start);

    if (MEMCMP("null", json_obj.buffer, json_obj.bufferLen) == 0) {
        return parser_no_data;
    }

    *json_token_index = token_index;

    return parser_ok;
}

parser_error_t parser_getNthClistElement(parsed_json_t *json_obj, uint8_t clist_array_idx) {
    uint16_t token_index = 0;
    array_get_nth_element(json_obj, 0, clist_array_idx, &token_index);
    json_parse(json_obj, json_obj->buffer + json_obj->tokens[token_index].start, json_obj->tokens[token_index].end - json_obj->tokens[token_index].start);

    return parser_ok;
}

parser_error_t parser_getGasObject(uint16_t *json_token_index) {
    uint16_t token_index = 0;
    parsed_json_t *json_all = &parser_tx_obj.tx_json.json;
    uint16_t name_token_index = 0;
    
    for (uint16_t i = 0; i < parser_getNumberOfClistElements(); i++) {
        array_get_nth_element(json_all, *json_token_index, i, &token_index);

        object_get_value(json_all, token_index, "name", &name_token_index);
        if (MEMCMP("coin.GAS", json_all->buffer + json_all->tokens[name_token_index].start,
            json_all->tokens[name_token_index].end - json_all->tokens[name_token_index].start) == 0) {
            *json_token_index = token_index;
            return parser_ok;
        }
    }

    return parser_no_data;
}

parser_error_t parser_getChainId(parsed_json_t *json_obj) {
    uint16_t token_index = 0;
    object_get_value(&parser_tx_obj.tx_json.json, 0, "chainId", &token_index);
    json_parse(json_obj, parser_tx_obj.tx_json.json.buffer + parser_tx_obj.tx_json.json.tokens[token_index].start, parser_tx_obj.tx_json.json.tokens[token_index].end - parser_tx_obj.tx_json.json.tokens[token_index].start);

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
