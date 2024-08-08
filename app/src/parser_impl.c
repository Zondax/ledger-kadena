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


parser_error_t parser_getJsonValueAsString(const char *key_name, char *outVal, uint16_t *outValLen) {
    uint16_t token_index = 0;

    // Search token_index to access the parsed JSON object
    object_get_value(&parser_tx_obj.tx_json.json, 0, key_name, &token_index);

    *outValLen = (parser_tx_obj.tx_json.json.tokens[token_index].end - parser_tx_obj.tx_json.json.tokens[token_index].start);
    strncpy(outVal, parser_tx_obj.tx_json.json.buffer + parser_tx_obj.tx_json.json.tokens[token_index].start, *outValLen);

    return parser_ok;
}

parser_error_t parser_getTransactionParams(uint8_t tx_index, char *amount, uint16_t *amount_size, char *from, uint16_t *from_size, char *to, uint16_t *to_size) {
    parsed_json_t json_clist;
    parsed_json_t json_tx;
    parsed_json_t json_args;
    uint16_t token_index = 0;

    object_get_value(&parser_tx_obj.tx_json.json, 0, "clist", &token_index);

    json_parse(&json_clist, parser_tx_obj.tx_json.json.buffer + parser_tx_obj.tx_json.json.tokens[token_index].start, parser_tx_obj.tx_json.json.tokens[token_index].end - parser_tx_obj.tx_json.json.tokens[token_index].start);
    
    array_get_nth_element(&json_clist, 0, 0, &token_index);

    json_parse(&json_tx, json_clist.buffer + json_clist.tokens[token_index].start, json_clist.tokens[token_index].end - json_clist.tokens[token_index].start);

    object_get_value(&json_tx, 0, "args", &token_index);

    json_parse(&json_args, json_tx.buffer + json_tx.tokens[token_index].start, json_tx.tokens[token_index].end - json_tx.tokens[token_index].start);

    array_get_nth_element(&json_args, 0, 0, &token_index);
    strncpy(from, json_args.buffer + json_args.tokens[token_index].start, json_args.tokens[token_index].end - json_args.tokens[token_index].start);
    *from_size = json_args.tokens[token_index].end - json_args.tokens[token_index].start;
    from[*from_size] = '\0';

    array_get_nth_element(&json_args, 0, 1, &token_index);
    strncpy(to, json_args.buffer + json_args.tokens[token_index].start, json_args.tokens[token_index].end - json_args.tokens[token_index].start);
    *to_size = json_args.tokens[token_index].end - json_args.tokens[token_index].start;
    to[*to_size] = '\0';

    array_get_nth_element(&json_args, 0, 2, &token_index);
    strncpy(amount, json_args.buffer + json_args.tokens[token_index].start, json_args.tokens[token_index].end - json_args.tokens[token_index].start);
    *amount_size = json_args.tokens[token_index].end - json_args.tokens[token_index].start;
    amount[*amount_size] = '\0';

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
