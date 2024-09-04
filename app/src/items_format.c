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
#include "parser_impl.h"

static items_error_t items_findChunkIndex(const char *key, uint8_t *outPos);

extern char base64_hash[45];

items_error_t items_stdToDisplayString(item_t item, char *outVal, uint16_t outValLen) {
    uint8_t *buffer = NULL;
    uint16_t len = 0;

    if (parser_usingChunks()) {
        uint8_t chunk_index;
        CHECK_ITEMS_ERROR(items_findChunkIndex(item.key, &chunk_index));
        len = parser_getChunks()[chunk_index].len;
        buffer = (uint8_t *)parser_getChunks()[chunk_index].data;
    } else {
        const parsed_json_t *json_all = &(parser_getParserJsonObj()->json);
        const jsmntok_t *token = &(json_all->tokens[item.json_token_index]);
        len = token->end - token->start;

        if (len == 0) return items_length_zero;

        if (len >= outValLen) {
            return items_data_too_large;
        }

        buffer = (uint8_t *)json_all->buffer + token->start;
    }

    snprintf(outVal, outValLen, "%.*s", len, buffer);

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

items_error_t items_hashWarningToDisplayString(__Z_UNUSED item_t item, char *outVal, uint16_t outValLen) {
    uint16_t len = sizeof(HASH_WARNING_TEXT);

    if (len > outValLen) return items_data_too_large;

    snprintf(outVal, len, HASH_WARNING_TEXT);
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
    const char *amount;
    const char *to;
    const char *from;
    uint8_t amount_len = 0;
    uint8_t to_len = 0;
    uint8_t from_len = 0;
    
    if (parser_usingChunks()) {
        chunk_t *chunks = parser_getChunks();
        amount = chunks[AMOUNT_POS].data;
        amount_len = chunks[AMOUNT_POS].len;
        to = chunks[RECIPIENT_POS].data;
        to_len = chunks[RECIPIENT_POS].len;
        from = chunks[PUBKEY_POS].data;
        from_len = chunks[PUBKEY_POS].len;
    } else {
        parsed_json_t *json_all = &(parser_getParserJsonObj()->json);
        uint16_t item_token_index = item.json_token_index;
        uint16_t token_index = 0;

        PARSER_TO_ITEMS_ERROR(object_get_value(json_all, item_token_index, "args", &token_index));
        PARSER_TO_ITEMS_ERROR(parser_arrayElementToString(token_index, 0, &from, &from_len));
        PARSER_TO_ITEMS_ERROR(parser_arrayElementToString(token_index, 1, &to, &to_len));
        PARSER_TO_ITEMS_ERROR(parser_arrayElementToString(token_index, 2, &amount, &amount_len));
    }

    uint16_t required_len = amount_len + from_len + to_len + strlen(" from ") + strlen(" to ") + 4 * sizeof("\"");

    if (required_len > outValLen) {
        return items_data_too_large;
    }

    snprintf(outVal, outValLen, "%.*s from \"%.*s\" to \"%.*s\"", amount_len, amount, from_len, from, to_len, to);

    return items_ok;
}

items_error_t items_crossTransferToDisplayString(item_t item, char *outVal, uint16_t outValLen) {
    const char *amount;
    const char *to;
    const char *from;
    const char *chain;
    uint8_t amount_len = 0;
    uint8_t to_len = 0;
    uint8_t from_len = 0;
    uint8_t chain_len = 0;

    if (parser_usingChunks()) {
        chunk_t *chunks = parser_getChunks();
        amount = chunks[AMOUNT_POS].data;
        amount_len = chunks[AMOUNT_POS].len;
        to = chunks[RECIPIENT_POS].data;
        to_len = chunks[RECIPIENT_POS].len;
        from = chunks[PUBKEY_POS].data;
        from_len = chunks[PUBKEY_POS].len;
        chain = chunks[CHAIN_ID_POS].data;
        chain_len = chunks[CHAIN_ID_POS].len;
    } else {
        parsed_json_t *json_all = &(parser_getParserJsonObj()->json);
        uint16_t item_token_index = item.json_token_index;
        uint16_t token_index = 0;

        PARSER_TO_ITEMS_ERROR(object_get_value(json_all, item_token_index, "args", &token_index));
        PARSER_TO_ITEMS_ERROR(parser_arrayElementToString(token_index, 0, &from, &from_len));
        PARSER_TO_ITEMS_ERROR(parser_arrayElementToString(token_index, 1, &to, &to_len));
        PARSER_TO_ITEMS_ERROR(parser_arrayElementToString(token_index, 2, &amount, &amount_len));
        PARSER_TO_ITEMS_ERROR(parser_arrayElementToString(token_index, 3, &chain, &chain_len));
    }

    uint16_t required_len = amount_len + from_len + to_len + chain_len + strlen("Cross-chain ") + strlen(" from ") +
                            strlen(" to ") + 6 * strlen("\"") + strlen(" to chain ");

    if (required_len > outValLen) {
        return items_data_too_large;
    }

    snprintf(outVal, outValLen, "Cross-chain %.*s from \"%.*s\" to \"%.*s\" to chain \"%.*s\"", amount_len, amount, from_len,
             from, to_len, to, chain_len, chain);

    return items_ok;
}

items_error_t items_rotateToDisplayString(item_t item, char *outVal, uint16_t outValLen) {
    uint16_t token_index = 0;
    uint16_t item_token_index = item.json_token_index;
    parsed_json_t *json_all = &(parser_getParserJsonObj()->json);
    jsmntok_t *token;

    PARSER_TO_ITEMS_ERROR(object_get_value(json_all, item_token_index, "args", &token_index));
    PARSER_TO_ITEMS_ERROR(array_get_nth_element(json_all, token_index, 0, &token_index));
    token = &(json_all->tokens[token_index]);

    outValLen = token->end - token->start + sizeof("\"\"");
    snprintf(outVal, outValLen, "\"%s\"", json_all->buffer + token->start);

    return items_ok;
}

items_error_t items_gasToDisplayString(__Z_UNUSED item_t item, char *outVal, uint16_t outValLen) {
    const char *gasLimit;
    const char *gasPrice;
    uint8_t gasLimit_len;
    uint8_t gasPrice_len;
    
    if (parser_usingChunks()) {
        chunk_t *chunks = parser_getChunks();
        gasLimit = chunks[GAS_LIMIT_POS].data;
        gasLimit_len = chunks[GAS_LIMIT_POS].len;
        gasPrice = chunks[GAS_PRICE_POS].data;
        gasPrice_len = chunks[GAS_PRICE_POS].len;
    } else {
        parsed_json_t *json_all = &(parser_getParserJsonObj()->json);
        uint16_t item_token_index = item.json_token_index;
        uint16_t meta_token_index = item.json_token_index;
        jsmntok_t *token;

        PARSER_TO_ITEMS_ERROR(object_get_value(json_all, item_token_index, JSON_GAS_LIMIT, &item_token_index));
        token = &(json_all->tokens[item_token_index]);
        gasLimit = json_all->buffer + token->start;
        gasLimit_len = token->end - token->start;

        item_token_index = meta_token_index;

        PARSER_TO_ITEMS_ERROR(object_get_value(json_all, item_token_index, JSON_GAS_PRICE, &item_token_index));
        token = &(json_all->tokens[item_token_index]);
        gasPrice = json_all->buffer + token->start;
        gasPrice_len = token->end - token->start;
    }

    uint16_t required_len = gasLimit_len + gasPrice_len + strlen("at most ") + strlen(" at price ");
    if (required_len > outValLen) {
        return items_data_too_large;
    }

    snprintf(outVal, outValLen, "at most %.*s at price %.*s", gasLimit_len, gasLimit, gasPrice_len, gasPrice);

    return items_ok;
}

items_error_t items_hashToDisplayString(__Z_UNUSED item_t item, char *outVal, uint16_t outValLen) {
    // TODO: why -2 here?
    uint16_t len = sizeof(base64_hash) - 2;
    if (len >= outValLen) return items_data_too_large;

    snprintf(outVal, outValLen, "%.*s", len, base64_hash);
    return items_ok;
}

items_error_t items_unknownCapabilityToDisplayString(item_t item, char *outVal, uint16_t outValLen) {
    uint16_t token_index = 0;
    uint16_t args_count = 0;
    uint8_t outVal_idx = 0;
    parsed_json_t *json_all = &(parser_getParserJsonObj()->json);
    uint16_t item_token_index = item.json_token_index;
    jsmntok_t *token;
    uint16_t len = 0;

    PARSER_TO_ITEMS_ERROR(object_get_value(json_all, item_token_index, JSON_NAME, &token_index));
    token = &(json_all->tokens[token_index]);

    len = token->end - token->start;

    if (len == 0) return items_length_zero;

    if (len >= outValLen) {
        return items_data_too_large;
    }

    snprintf(outVal, outValLen, "name: %.*s, ]}],\"", len, json_all->buffer + token->start);

    // outVal_idx is after the , of %.*s
    outVal_idx = sizeof("name: ") + len + 1;

    if (item.can_display == bool_false) {
        const char *msg = "args cannot be displayed on Ledger";
        uint16_t len_msg = strlen(msg);

        if (outVal_idx + len_msg >= outValLen) {
            return items_data_too_large;
        }

        snprintf(outVal + outVal_idx, len_msg + 1, "%s", msg);
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
        const char *msg = "no args";
        uint16_t len_msg = strlen(msg);

        if (outVal_idx + len_msg >= outValLen) {
            return items_data_too_large;
        }

        snprintf(outVal + outVal_idx, len + 1, "%s", msg);
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

static items_error_t items_findChunkIndex(const char *key, uint8_t *outPos) {
    if (MEMCMP(key, "On Network", strlen("On Network")) == 0) {
        *outPos = NETWORK_POS;
        return items_ok;
    } else if (MEMCMP(key, "Of Key", strlen("Of Key")) == 0) {
        *outPos = PUBKEY_POS;
        return items_ok;
    } else if (MEMCMP(key, "On Chain", strlen("On Chain")) == 0) {
        *outPos = CHAIN_ID_POS;
        return items_ok;
    } else {
        return items_error;
    }
}