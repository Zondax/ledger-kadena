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
#include "items.h"

tx_json_t *parser_tx_obj;

parser_error_t _read_json_tx(parser_context_t *c, tx_json_t *v) {
    parser_tx_obj = v;

    CHECK_ERROR(json_parse(&(parser_tx_obj->json), (const char *) c->buffer,
                           c->bufferLen));

    parser_tx_obj->tx = (const char *) c->buffer;
    parser_tx_obj->flags.cache_valid = 0;
    parser_tx_obj->filter_msg_type_count = 0;
    parser_tx_obj->filter_msg_from_count = 0;

    return parser_ok;
}

tx_json_t *parser_getParserTxObj() {
    return parser_tx_obj;
}

parser_error_t parser_findPubKeyInClist(uint16_t key_token_index) {
    parsed_json_t *json_all = &parser_tx_obj->json;
    uint16_t token_index = 0;
    uint16_t clist_token_index = 0;
    uint16_t args_token_index = 0;
    uint16_t number_of_args = 0;
    uint16_t clist_element_count = 0;
    jsmntok_t *value_token;
    jsmntok_t *key_token;

    CHECK_ERROR(object_get_value(json_all, 0, JSON_SIGNERS, &clist_token_index));

    if (items_isNullField(clist_token_index)) {
        return parser_no_data;
    }

    array_get_nth_element(json_all, clist_token_index, 0, &clist_token_index);

    CHECK_ERROR(object_get_value(json_all, clist_token_index, JSON_CLIST, &clist_token_index));

    if (items_isNullField(clist_token_index)) {
        return parser_no_data;
    }

    for (uint16_t i = 0; i < clist_element_count; i++) {
        CHECK_ERROR(array_get_nth_element(json_all, clist_token_index, i, &args_token_index));
        CHECK_ERROR(object_get_value(json_all, args_token_index, JSON_ARGS, &args_token_index));
        CHECK_ERROR(array_get_element_count(json_all, args_token_index, &number_of_args));

        for (uint16_t j = 0; j < number_of_args; j++) {
            array_get_nth_element(json_all, args_token_index, j, &token_index);
            value_token = &(json_all->tokens[token_index]);
            key_token = &(json_all->tokens[key_token_index]);
            uint8_t offset = 0;

            // Key could possibly be prefixed with "k:"
            if (MEMCMP("k:", json_all->buffer + value_token->start, 2) == 0) {
                offset = 2;
            }

            if (MEMCMP(json_all->buffer + key_token->start,
                json_all->buffer + value_token->start + offset,
                key_token->end - key_token->start) == 0) {
                return parser_ok;
            }
        }
    }

    return parser_no_data;
}

parser_error_t parser_arrayElementToString(uint16_t json_token_index, uint16_t element_idx, char *outVal, uint8_t *outValLen) {
    uint16_t token_index = 0;
    parsed_json_t *json_all = &(parser_tx_obj->json);
    jsmntok_t *token;

    CHECK_ERROR(array_get_nth_element(json_all, json_token_index, element_idx, &token_index));
    token = &(json_all->tokens[token_index]);

    strncpy(outVal, json_all->buffer + token->start, token->end - token->start);
    *outValLen = token->end - token->start;
    outVal[*outValLen] = '\0';

    return parser_ok;
}

parser_error_t parser_validateMetaField() {
    const char *keywords[20] = {
        JSON_CREATION_TIME,
        JSON_TTL,
        JSON_GAS_LIMIT,
        JSON_CHAIN_ID,
        JSON_GAS_PRICE,
        JSON_SENDER
    };
    char meta_curr_key[20];
    uint16_t meta_token_index = 0;
    uint16_t meta_num_elements = 0;
    uint16_t key_token_idx = 0;
    parsed_json_t *json_all = &(parser_tx_obj->json);
    jsmntok_t *token;

    object_get_value(json_all, 0, JSON_META, &meta_token_index);

    if (!items_isNullField(meta_token_index)) {
        object_get_element_count(json_all, meta_token_index, &meta_num_elements);

        for (uint16_t i = 0; i < meta_num_elements; i++) {
            object_get_nth_key(json_all, meta_token_index, i, &key_token_idx);
            token = &(json_all->tokens[key_token_idx]);

            MEMCPY(meta_curr_key, json_all->buffer + token->start,
                token->end - token->start);
            meta_curr_key[token->end - token->start] = '\0';

            if (strcmp(keywords[i], meta_curr_key) != 0) {
                return parser_invalid_meta_field;
            }

            MEMZERO(meta_curr_key, sizeof(meta_curr_key));
        }
    }

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

bool items_isNullField(uint16_t json_token_index) {
    parsed_json_t *json_all = &(parser_getParserTxObj()->json);
    jsmntok_t *token = &(json_all->tokens[json_token_index]);

    return (MEMCMP("null", json_all->buffer + token->start, token->end - token->start) == 0);
}
