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

#include "crypto.h"
#include "crypto_helper.h"
#include "items.h"
#include "zxformat.h"

#define TRANSFER_FORMAT                                                                     \
    "{\"networkId\":\"%.*s\",\"payload\":{\"exec\":{\"data\":{},\"code\":\"(%.*s.transfer " \
    "\\\"k:%.*s\\\" \\\"k:%.*s\\\" %.*s)\"}},\"signers\":[{\"pubKey\":\"%.*s\",\"clist\":[" \
    "{\"args\":[\"k:%.*s\",\"k:%.*s\",%.*s],\"name\":\"%.*s.TRANSFER\"},"                   \
    "{\"args\":[],\"name\":\"coin.GAS\"}]}],\"meta\":{\"creationTime\":%.*s,"               \
    "\"ttl\":%.*s,\"gasLimit\":%.*s,\"chainId\":\"%.*s\",\"gasPrice\":%.*s,"                \
    "\"sender\":\"k:%.*s\"},\"nonce\":\"%.*s\"}"

#define TRANSFER_CREATE_FORMAT                                                                \
    "{\"networkId\":\"%.*s\",\"payload\":{\"exec\":{\"data\":{\"ks\":{\"pred\":\"keys-all\"," \
    "\"keys\":[\"%.*s\"]}},\"code\":\"(%.*s.transfer-create \\\"k:%.*s\\\" \\\"k:%.*s\\\" "   \
    "(read-keyset \\\"ks\\\") %.*s)\"}},\"signers\":[{\"pubKey\":\"%.*s\",\"clist\":["        \
    "{\"args\":[\"k:%.*s\",\"k:%.*s\",%.*s],\"name\":\"%.*s.TRANSFER\"},"                     \
    "{\"args\":[],\"name\":\"coin.GAS\"}]}],\"meta\":{\"creationTime\":%.*s,"                 \
    "\"ttl\":%.*s,\"gasLimit\":%.*s,\"chainId\":\"%.*s\",\"gasPrice\":%.*s,"                  \
    "\"sender\":\"k:%.*s\"},\"nonce\":\"%.*s\"}"

#define TRANSFER_CROSSCHAIN_FORMAT                                                                  \
    "{\"networkId\":\"%.*s\",\"payload\":{\"exec\":{\"data\":{\"ks\":{\"pred\":\"keys-all\","       \
    "\"keys\":[\"%.*s\"]}},\"code\":\"(%.*s.transfer-crosschain \\\"k:%.*s\\\" \\\"k:%.*s\\\" "     \
    "(read-keyset \\\"ks\\\") \\\"%.*s\\\" %.*s)\"}},\"signers\":[{\"pubKey\":\"%.*s\",\"clist\":[" \
    "{\"args\":[\"k:%.*s\",\"k:%.*s\",%.*s,\"%.*s\"],\"name\":\"%.*s.TRANSFER_XCHAIN\"},"           \
    "{\"args\":[],\"name\":\"coin.GAS\"}]}],\"meta\":{\"creationTime\":%.*s,"                       \
    "\"ttl\":%.*s,\"gasLimit\":%.*s,\"chainId\":\"%.*s\",\"gasPrice\":%.*s,"                        \
    "\"sender\":\"k:%.*s\"},\"nonce\":\"%.*s\"}"

#if defined(TARGET_NANOS)
#define INCREMENT_POINTER_NVM(inc)                                                            \
    {                                                                                         \
        if (ptr + inc > jsonTemplate + jsonTemplateSize) return parser_unexpected_buffer_end; \
        ptr += inc;                                                                           \
    }
#endif

#define RECIPIENT_POS 0
#define RECIPIENT_CHAIN_POS 1
#define NETWORK_POS 2
#define AMOUNT_POS 3
#define NAMESPACE_POS 4
#define MODULE_POS 5
#define GAS_PRICE_POS 6
#define GAS_LIMIT_POS 7
#define CREATION_TIME_POS 8
#define CHAIN_ID_POS 9
#define NONCE_POS 10
#define TTL_POS 11

static parser_error_t parser_readSingleByte(parser_context_t *ctx, uint8_t *byte);
static parser_error_t parser_readBytes(parser_context_t *ctx, uint8_t **bytes, uint16_t len);
static parser_error_t parser_formatTxTransfer(char *jsonTemplate, uint16_t jsonTemplateSize, uint16_t *jsonTemplateLen,
                                              uint16_t address_len, char *address, chunk_t *chunks);
static parser_error_t parser_formatTxTransferCreate(char *jsonTemplate, uint16_t jsonTemplateSize, uint16_t *jsonTemplateLen,
                                                    uint16_t address_len, char *address, chunk_t *chunks);
static parser_error_t parser_formatTxTransferCrosschain(char *jsonTemplate, uint16_t jsonTemplateSize,
                                                        uint16_t *jsonTemplateLen, uint16_t address_len, char *address,
                                                        chunk_t *chunks);

tx_json_t *parser_json_obj;
tx_hash_t *parser_hash_obj;

parser_error_t _read_json_tx(parser_context_t *c) {
    parser_json_obj = c->json;

    CHECK_ERROR(json_parse(&(parser_json_obj->json), (const char *)c->buffer, c->bufferLen));

    parser_json_obj->tx = (const char *)c->buffer;
    parser_json_obj->flags.cache_valid = 0;
    parser_json_obj->filter_msg_type_count = 0;
    parser_json_obj->filter_msg_from_count = 0;
    return parser_ok;
}

parser_error_t _read_hash_tx(parser_context_t *c) {
    parser_hash_obj = c->hash;

    MEMZERO(parser_hash_obj, sizeof(tx_hash_t));

    parser_hash_obj->tx = (const char *)c->buffer;
    parser_hash_obj->hash_len = c->bufferLen;

    return parser_ok;
}

tx_json_t *parser_getParserJsonObj() { return parser_json_obj; }

tx_hash_t *parser_getParserHashObj() { return parser_hash_obj; }

parser_error_t parser_findPubKeyInClist(uint16_t key_token_index) {
    parsed_json_t *json_all = &parser_json_obj->json;
    uint16_t token_index = 0;
    uint16_t clist_token_index = 0;
    uint16_t args_token_index = 0;
    uint16_t number_of_args = 0;
    uint16_t clist_element_count = 0;
    jsmntok_t *value_token;
    jsmntok_t *key_token;

    if (parser_getValidClist(&clist_token_index, &clist_element_count) != parser_ok) {
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

            if (MEMCMP(json_all->buffer + key_token->start, json_all->buffer + value_token->start + offset,
                       key_token->end - key_token->start) == 0) {
                return parser_ok;
            }
        }
    }

    return parser_no_data;
}

parser_error_t parser_arrayElementToString(uint16_t json_token_index, uint16_t element_idx, const char **outVal,
                                           uint8_t *outValLen) {
    uint16_t token_index = 0;
    parsed_json_t *json_all = &(parser_json_obj->json);
    jsmntok_t *token;
    uint16_t element_count = 0;

    CHECK_ERROR(array_get_element_count(json_all, json_token_index, &element_count));
    if (element_idx >= element_count) {
        return parser_no_data;
    }

    CHECK_ERROR(array_get_nth_element(json_all, json_token_index, element_idx, &token_index));
    token = &(json_all->tokens[token_index]);

    *outVal = json_all->buffer + token->start;
    *outValLen = token->end - token->start;

    return parser_ok;
}

parser_error_t parser_validateMetaField() {
    const char *keywords[20] = {JSON_CREATION_TIME, JSON_TTL, JSON_GAS_LIMIT, JSON_CHAIN_ID, JSON_GAS_PRICE, JSON_SENDER};
    char meta_curr_key[40];
    uint16_t meta_token_index = 0;
    uint16_t meta_num_elements = 0;
    uint16_t key_token_idx = 0;
    parsed_json_t *json_all = &(parser_json_obj->json);
    jsmntok_t *token;

    CHECK_ERROR(object_get_value(json_all, 0, JSON_META, &meta_token_index));

    if (!items_isNullField(meta_token_index)) {
        object_get_element_count(json_all, meta_token_index, &meta_num_elements);

        for (uint16_t i = 0; i < meta_num_elements; i++) {
            object_get_nth_key(json_all, meta_token_index, i, &key_token_idx);
            token = &(json_all->tokens[key_token_idx]);

            // Prevent buffer overflow in case of big key-value pair in meta field.
            if (token->end - token->start >= sizeof(meta_curr_key)) return parser_invalid_meta_field;

            MEMCPY(meta_curr_key, json_all->buffer + token->start, token->end - token->start);
            meta_curr_key[token->end - token->start] = '\0';

            if (strcmp(keywords[i], meta_curr_key) != 0) {
                return parser_invalid_meta_field;
            }

            MEMZERO(meta_curr_key, sizeof(meta_curr_key));
        }
    } else {
        return parser_no_data;
    }

    return parser_ok;
}

parser_error_t parser_getTxName(uint16_t token_index) {
    parsed_json_t *json_all = &(parser_json_obj->json);

    if (object_get_value(json_all, token_index, JSON_NAME, &token_index) == parser_ok) {
        uint16_t len = 0;
        jsmntok_t *token;

        token = &(json_all->tokens[token_index]);

        len = token->end - token->start;

        if (len == 0) return parser_no_data;

        if (strlen("coin.TRANSFER") == len && MEMCMP("coin.TRANSFER", json_all->buffer + token->start, len) == 0) {
            return parser_name_tx_transfer;
        } else if (strlen("coin.TRANSFER_XCHAIN") == len &&
                   MEMCMP("coin.TRANSFER_XCHAIN", json_all->buffer + token->start, len) == 0) {
            return parser_name_tx_transfer_xchain;
        } else if (strlen("coin.ROTATE") == len && MEMCMP("coin.ROTATE", json_all->buffer + token->start, len) == 0) {
            return parser_name_rotate;
        } else if (strlen("coin.GAS") == len || MEMCMP("coin.GAS", json_all->buffer + token->start, len) == 0) {
            return parser_name_gas;
        }
    }

    return parser_no_data;
}

parser_error_t parser_getValidClist(uint16_t *clist_token_index, uint16_t *num_args) {
    parsed_json_t *json_all = &(parser_json_obj->json);

    CHECK_ERROR(object_get_value(json_all, 0, JSON_SIGNERS, clist_token_index));

    if (!items_isNullField(*clist_token_index)) {
        CHECK_ERROR(array_get_nth_element(json_all, *clist_token_index, 0, clist_token_index));

        if (object_get_value(json_all, *clist_token_index, JSON_CLIST, clist_token_index) == parser_ok) {
            if (!items_isNullField(*clist_token_index)) {
                CHECK_ERROR(array_get_element_count(json_all, *clist_token_index, num_args));
                return parser_ok;
            }
        }
    }

    return parser_no_data;
}

bool items_isNullField(uint16_t json_token_index) {
    parsed_json_t *json_all = &(parser_getParserJsonObj()->json);
    jsmntok_t *token = &(json_all->tokens[json_token_index]);

    if (token->end - token->start != sizeof("null") - 1) return false;

    return (MEMCMP("null", json_all->buffer + token->start, token->end - token->start) == 0);
}

parser_error_t parser_createJsonTemplate(parser_context_t *ctx, char *jsonTemplate, uint16_t jsonTemplateSize,
                                         uint16_t *jsonTemplateLen) {
    // read tx_type
    uint8_t tx_type = 0;
    parser_readSingleByte(ctx, &tx_type);

    chunk_t chunks[12];

    for (int i = 0; i < 12; i++) {
        parser_readSingleByte(ctx, &chunks[i].len);
        if (chunks[i].len > 0) {
            parser_readBytes(ctx, (uint8_t **)&chunks[i].data, chunks[i].len);
        } else {
            chunks[i].data = (char *)"";
        }
    }

    char address[65] = {0};
#if defined(TARGET_NANOS) || defined(TARGET_NANOX) || defined(TARGET_NANOS2) || defined(TARGET_STAX) || defined(TARGET_FLEX)
    uint8_t pubkey[PUB_KEY_LENGTH] = {0};
    uint16_t pubkey_len = 0;

    if (crypto_fillAddress(pubkey, sizeof(pubkey), &pubkey_len) != zxerr_ok) {
        return parser_unexpected_error;
    }

    uint32_t address_len = array_to_hexstr(address, sizeof(address), pubkey, PUB_KEY_LENGTH);
#else
    // Dummy address for cpp_test
    uint32_t address_len =
        snprintf(address, sizeof(address), "%s", "1234567890123456789012345678901234567890123456789012345678901234");
#endif

    switch (tx_type) {
        case TX_TYPE_TRANSFER: {
            parser_formatTxTransfer(jsonTemplate, jsonTemplateSize, jsonTemplateLen, address_len, address, chunks);
            break;
        }
        case TX_TYPE_TRANSFER_CREATE: {
            parser_formatTxTransferCreate(jsonTemplate, jsonTemplateSize, jsonTemplateLen, address_len, address, chunks);
            break;
        }
        case TX_TYPE_TRANSFER_CROSSCHAIN: {
            parser_formatTxTransferCrosschain(jsonTemplate, jsonTemplateSize, jsonTemplateLen, address_len, address, chunks);
            break;
        }
        default:
            return parser_no_data;
    }

    return parser_ok;
}

static parser_error_t parser_readSingleByte(parser_context_t *ctx, uint8_t *byte) {
    if (ctx->offset >= ctx->bufferLen) {
        return parser_unexpected_buffer_end;
    }

    *byte = ctx->buffer[ctx->offset];
    ctx->offset++;
    return parser_ok;
}

static parser_error_t parser_readBytes(parser_context_t *ctx, uint8_t **bytes, uint16_t len) {
    if (ctx->offset + len > ctx->bufferLen) {
        return parser_unexpected_buffer_end;
    }

    *bytes = (uint8_t *)(ctx->buffer + ctx->offset);
    ctx->offset += len;
    return parser_ok;
}

static parser_error_t parser_formatTxTransfer(char *jsonTemplate, uint16_t jsonTemplateSize, uint16_t *jsonTemplateLen,
                                              uint16_t address_len, char *address, chunk_t *chunks) {
    char namespace_and_module[30] = {0};
    if (chunks[NAMESPACE_POS].len > 0 && chunks[MODULE_POS].len > 0) {
        snprintf(namespace_and_module, sizeof(namespace_and_module), "%.*s.%.*s", chunks[NAMESPACE_POS].len,
                 chunks[NAMESPACE_POS].data, chunks[MODULE_POS].len, chunks[MODULE_POS].data);
    } else {
        snprintf(namespace_and_module, sizeof(namespace_and_module), "%s", "coin");
    }

#if !defined(TARGET_NANOS)
    snprintf(jsonTemplate, jsonTemplateSize, TRANSFER_FORMAT, chunks[NETWORK_POS].len, chunks[NETWORK_POS].data,
             (int)strlen(namespace_and_module), namespace_and_module, address_len, address, chunks[RECIPIENT_POS].len,
             chunks[RECIPIENT_POS].data, chunks[AMOUNT_POS].len, chunks[AMOUNT_POS].data, address_len, address, address_len,
             address, chunks[RECIPIENT_POS].len, chunks[RECIPIENT_POS].data, chunks[AMOUNT_POS].len, chunks[AMOUNT_POS].data,
             (int)strlen(namespace_and_module), namespace_and_module, chunks[CREATION_TIME_POS].len,
             chunks[CREATION_TIME_POS].data, chunks[TTL_POS].len, chunks[TTL_POS].data, chunks[GAS_LIMIT_POS].len,
             chunks[GAS_LIMIT_POS].data, chunks[CHAIN_ID_POS].len, chunks[CHAIN_ID_POS].data, chunks[GAS_PRICE_POS].len,
             chunks[GAS_PRICE_POS].data, address_len, address, chunks[NONCE_POS].len, chunks[NONCE_POS].data);

    *jsonTemplateLen = strlen(jsonTemplate);
#else
    // For nanoS we need to use flash memory for the json template
    char *ptr = jsonTemplate;

    MEMCPY_NV((void *)ptr, (void *)"{\"networkId\":\"", 14);
    INCREMENT_POINTER_NVM(14)
    MEMCPY_NV((void *)ptr, chunks[NETWORK_POS].data, chunks[NETWORK_POS].len);
    INCREMENT_POINTER_NVM(chunks[NETWORK_POS].len)
    MEMCPY_NV((void *)ptr, (void *)"\",\"payload\":{\"exec\":{\"data\":{},\"code\":\"", 39);
    INCREMENT_POINTER_NVM(39)
    MEMCPY_NV((void *)ptr, (void *)"(", 1);
    INCREMENT_POINTER_NVM(1)
    MEMCPY_NV((void *)ptr, namespace_and_module, strlen(namespace_and_module));
    INCREMENT_POINTER_NVM(strlen(namespace_and_module))
    MEMCPY_NV((void *)ptr, (void *)".transfer \\\"k:", 14);
    INCREMENT_POINTER_NVM(14)
    MEMCPY_NV((void *)ptr, address, address_len);
    INCREMENT_POINTER_NVM(address_len)
    MEMCPY_NV((void *)ptr, (void *)"\\\" \\\"k:", 7);
    INCREMENT_POINTER_NVM(7)
    MEMCPY_NV((void *)ptr, chunks[RECIPIENT_POS].data, chunks[RECIPIENT_POS].len);
    INCREMENT_POINTER_NVM(chunks[RECIPIENT_POS].len)
    MEMCPY_NV((void *)ptr, (void *)"\\\" ", 3);
    INCREMENT_POINTER_NVM(3)
    MEMCPY_NV((void *)ptr, chunks[AMOUNT_POS].data, chunks[AMOUNT_POS].len);
    INCREMENT_POINTER_NVM(chunks[AMOUNT_POS].len)
    MEMCPY_NV((void *)ptr, (void *)")\"}},\"signers\":[{\"pubKey\":\"", 27);
    INCREMENT_POINTER_NVM(27)
    MEMCPY_NV((void *)ptr, address, address_len);
    INCREMENT_POINTER_NVM(address_len)
    MEMCPY_NV((void *)ptr, (void *)"\",\"clist\":[{\"args\":[\"k:", 23);
    INCREMENT_POINTER_NVM(23)
    MEMCPY_NV((void *)ptr, address, address_len);
    INCREMENT_POINTER_NVM(address_len)
    MEMCPY_NV((void *)ptr, (void *)"\",\"k:", 5);
    INCREMENT_POINTER_NVM(5)
    MEMCPY_NV((void *)ptr, chunks[RECIPIENT_POS].data, chunks[RECIPIENT_POS].len);
    INCREMENT_POINTER_NVM(chunks[RECIPIENT_POS].len)
    MEMCPY_NV((void *)ptr, (void *)"\",", 2);
    INCREMENT_POINTER_NVM(2)
    MEMCPY_NV((void *)ptr, chunks[AMOUNT_POS].data, chunks[AMOUNT_POS].len);
    INCREMENT_POINTER_NVM(chunks[AMOUNT_POS].len)
    MEMCPY_NV((void *)ptr, (void *)"],\"name\":\"", 10);
    INCREMENT_POINTER_NVM(10)
    MEMCPY_NV((void *)ptr, namespace_and_module, strlen(namespace_and_module));
    INCREMENT_POINTER_NVM(strlen(namespace_and_module))
    MEMCPY_NV((void *)ptr, (void *)".TRANSFER\"},{\"args\":[],\"name\":\"coin.GAS\"}]}],\"meta\":{\"creationTime\":", 68);
    INCREMENT_POINTER_NVM(68)
    MEMCPY_NV((void *)ptr, chunks[CREATION_TIME_POS].data, chunks[CREATION_TIME_POS].len);
    INCREMENT_POINTER_NVM(chunks[CREATION_TIME_POS].len)
    MEMCPY_NV((void *)ptr, (void *)",\"ttl\":", 7);
    INCREMENT_POINTER_NVM(7)
    MEMCPY_NV((void *)ptr, chunks[TTL_POS].data, chunks[TTL_POS].len);
    INCREMENT_POINTER_NVM(chunks[TTL_POS].len)
    MEMCPY_NV((void *)ptr, (void *)",\"gasLimit\":", 12);
    INCREMENT_POINTER_NVM(12)
    MEMCPY_NV((void *)ptr, chunks[GAS_LIMIT_POS].data, chunks[GAS_LIMIT_POS].len);
    INCREMENT_POINTER_NVM(chunks[GAS_LIMIT_POS].len)
    MEMCPY_NV((void *)ptr, (void *)",\"chainId\":\"", 12);
    INCREMENT_POINTER_NVM(12)
    MEMCPY_NV((void *)ptr, chunks[CHAIN_ID_POS].data, chunks[CHAIN_ID_POS].len);
    INCREMENT_POINTER_NVM(chunks[CHAIN_ID_POS].len)
    MEMCPY_NV((void *)ptr, (void *)"\",\"gasPrice\":", 13);
    INCREMENT_POINTER_NVM(13)
    MEMCPY_NV((void *)ptr, chunks[GAS_PRICE_POS].data, chunks[GAS_PRICE_POS].len);
    INCREMENT_POINTER_NVM(chunks[GAS_PRICE_POS].len)
    MEMCPY_NV((void *)ptr, (void *)",\"sender\":\"k:", 13);
    INCREMENT_POINTER_NVM(13)
    MEMCPY_NV((void *)ptr, address, address_len);
    INCREMENT_POINTER_NVM(address_len)
    MEMCPY_NV((void *)ptr, (void *)"\"},\"nonce\":\"", 12);
    INCREMENT_POINTER_NVM(12)
    MEMCPY_NV((void *)ptr, chunks[NONCE_POS].data, chunks[NONCE_POS].len);
    INCREMENT_POINTER_NVM(chunks[NONCE_POS].len)
    MEMCPY_NV((void *)ptr, (void *)"\"}", 2);
    INCREMENT_POINTER_NVM(2)

    *jsonTemplateLen = ptr - jsonTemplate;
#endif

    return parser_ok;
}

static parser_error_t parser_formatTxTransferCreate(char *jsonTemplate, uint16_t jsonTemplateSize, uint16_t *jsonTemplateLen,
                                                    uint16_t address_len, char *address, chunk_t *chunks) {
    char namespace_and_module[30] = {0};
    if (chunks[NAMESPACE_POS].len > 0 && chunks[MODULE_POS].len > 0) {
        snprintf(namespace_and_module, sizeof(namespace_and_module), "%.*s.%.*s", chunks[NAMESPACE_POS].len,
                 chunks[NAMESPACE_POS].data, chunks[MODULE_POS].len, chunks[MODULE_POS].data);
    } else {
        snprintf(namespace_and_module, sizeof(namespace_and_module), "%s", "coin");
    }

#if !defined(TARGET_NANOS)
    snprintf(jsonTemplate, jsonTemplateSize, TRANSFER_CREATE_FORMAT, chunks[NETWORK_POS].len, chunks[NETWORK_POS].data,
             chunks[RECIPIENT_POS].len, chunks[RECIPIENT_POS].data, (int)strlen(namespace_and_module), namespace_and_module,
             address_len, address, chunks[RECIPIENT_POS].len, chunks[RECIPIENT_POS].data, chunks[AMOUNT_POS].len,
             chunks[AMOUNT_POS].data, address_len, address, address_len, address, chunks[RECIPIENT_POS].len,
             chunks[RECIPIENT_POS].data, chunks[AMOUNT_POS].len, chunks[AMOUNT_POS].data, (int)strlen(namespace_and_module),
             namespace_and_module, chunks[CREATION_TIME_POS].len, chunks[CREATION_TIME_POS].data, chunks[TTL_POS].len,
             chunks[TTL_POS].data, chunks[GAS_LIMIT_POS].len, chunks[GAS_LIMIT_POS].data, chunks[CHAIN_ID_POS].len,
             chunks[CHAIN_ID_POS].data, chunks[GAS_PRICE_POS].len, chunks[GAS_PRICE_POS].data, address_len, address,
             chunks[NONCE_POS].len, chunks[NONCE_POS].data);

    *jsonTemplateLen = strlen(jsonTemplate);
#else
    // For nanoS we need to use flash memory for the json template
    char *ptr = jsonTemplate;

    MEMCPY_NV((void *)ptr, (void *)"{\"networkId\":\"", 14);
    INCREMENT_POINTER_NVM(14)
    MEMCPY_NV((void *)ptr, chunks[NETWORK_POS].data, chunks[NETWORK_POS].len);
    INCREMENT_POINTER_NVM(chunks[NETWORK_POS].len)
    MEMCPY_NV((void *)ptr, (void *)"\",\"payload\":{\"exec\":{\"data\":{\"ks\":{\"pred\":\"keys-all\",\"keys\":[\"", 62);
    INCREMENT_POINTER_NVM(62)
    MEMCPY_NV((void *)ptr, chunks[RECIPIENT_POS].data, chunks[RECIPIENT_POS].len);
    INCREMENT_POINTER_NVM(chunks[RECIPIENT_POS].len)
    MEMCPY_NV((void *)ptr, (void *)"\"]}},\"code\":\"(", 14);
    INCREMENT_POINTER_NVM(14)
    MEMCPY_NV((void *)ptr, namespace_and_module, strlen(namespace_and_module));
    INCREMENT_POINTER_NVM(strlen(namespace_and_module))
    MEMCPY_NV((void *)ptr, (void *)".transfer-create \\\"k:", 21);
    INCREMENT_POINTER_NVM(21)
    MEMCPY_NV((void *)ptr, address, address_len);
    INCREMENT_POINTER_NVM(address_len)
    MEMCPY_NV((void *)ptr, (void *)"\\\" \\\"k:", 7);
    INCREMENT_POINTER_NVM(7)
    MEMCPY_NV((void *)ptr, chunks[RECIPIENT_POS].data, chunks[RECIPIENT_POS].len);
    INCREMENT_POINTER_NVM(chunks[RECIPIENT_POS].len)
    MEMCPY_NV((void *)ptr, (void *)"\\\" (read-keyset \\\"ks\\\") ", 24);
    INCREMENT_POINTER_NVM(24)
    MEMCPY_NV((void *)ptr, chunks[AMOUNT_POS].data, chunks[AMOUNT_POS].len);
    INCREMENT_POINTER_NVM(chunks[AMOUNT_POS].len)
    MEMCPY_NV((void *)ptr, (void *)")\"}},\"signers\":[{\"pubKey\":\"", 27);
    INCREMENT_POINTER_NVM(27)
    MEMCPY_NV((void *)ptr, address, address_len);
    INCREMENT_POINTER_NVM(address_len)
    MEMCPY_NV((void *)ptr, (void *)"\",\"clist\":[{\"args\":[\"k:", 23);
    INCREMENT_POINTER_NVM(23)
    MEMCPY_NV((void *)ptr, address, address_len);
    INCREMENT_POINTER_NVM(address_len)
    MEMCPY_NV((void *)ptr, (void *)"\",\"k:", 5);
    INCREMENT_POINTER_NVM(5)
    MEMCPY_NV((void *)ptr, chunks[RECIPIENT_POS].data, chunks[RECIPIENT_POS].len);
    INCREMENT_POINTER_NVM(chunks[RECIPIENT_POS].len)
    MEMCPY_NV((void *)ptr, (void *)"\",", 2);
    INCREMENT_POINTER_NVM(2)
    MEMCPY_NV((void *)ptr, chunks[AMOUNT_POS].data, chunks[AMOUNT_POS].len);
    INCREMENT_POINTER_NVM(chunks[AMOUNT_POS].len)
    MEMCPY_NV((void *)ptr, (void *)"],\"name\":\"", 10);
    INCREMENT_POINTER_NVM(10)
    MEMCPY_NV((void *)ptr, namespace_and_module, strlen(namespace_and_module));
    INCREMENT_POINTER_NVM(strlen(namespace_and_module))
    MEMCPY_NV((void *)ptr, (void *)".TRANSFER\"},{\"args\":[],\"name\":\"coin.GAS\"}]}],\"meta\":{\"creationTime\":", 68);
    INCREMENT_POINTER_NVM(68)
    MEMCPY_NV((void *)ptr, chunks[CREATION_TIME_POS].data, chunks[CREATION_TIME_POS].len);
    INCREMENT_POINTER_NVM(chunks[CREATION_TIME_POS].len)
    MEMCPY_NV((void *)ptr, (void *)",\"ttl\":", 7);
    INCREMENT_POINTER_NVM(7)
    MEMCPY_NV((void *)ptr, chunks[TTL_POS].data, chunks[TTL_POS].len);
    INCREMENT_POINTER_NVM(chunks[TTL_POS].len)
    MEMCPY_NV((void *)ptr, (void *)",\"gasLimit\":", 12);
    INCREMENT_POINTER_NVM(12)
    MEMCPY_NV((void *)ptr, chunks[GAS_LIMIT_POS].data, chunks[GAS_LIMIT_POS].len);
    INCREMENT_POINTER_NVM(chunks[GAS_LIMIT_POS].len)
    MEMCPY_NV((void *)ptr, (void *)",\"chainId\":\"", 12);
    INCREMENT_POINTER_NVM(12)
    MEMCPY_NV((void *)ptr, chunks[CHAIN_ID_POS].data, chunks[CHAIN_ID_POS].len);
    INCREMENT_POINTER_NVM(chunks[CHAIN_ID_POS].len)
    MEMCPY_NV((void *)ptr, (void *)"\",\"gasPrice\":", 13);
    INCREMENT_POINTER_NVM(13)
    MEMCPY_NV((void *)ptr, chunks[GAS_PRICE_POS].data, chunks[GAS_PRICE_POS].len);
    INCREMENT_POINTER_NVM(chunks[GAS_PRICE_POS].len)
    MEMCPY_NV((void *)ptr, (void *)",\"sender\":\"k:", 13);
    INCREMENT_POINTER_NVM(13)
    MEMCPY_NV((void *)ptr, address, address_len);
    INCREMENT_POINTER_NVM(address_len)
    MEMCPY_NV((void *)ptr, (void *)"\"},\"nonce\":\"", 12);
    INCREMENT_POINTER_NVM(12)
    MEMCPY_NV((void *)ptr, chunks[NONCE_POS].data, chunks[NONCE_POS].len);
    INCREMENT_POINTER_NVM(chunks[NONCE_POS].len)
    MEMCPY_NV((void *)ptr, (void *)"\"}", 2);
    INCREMENT_POINTER_NVM(2)

    *jsonTemplateLen = ptr - jsonTemplate;
#endif

    return parser_ok;
}

static parser_error_t parser_formatTxTransferCrosschain(char *jsonTemplate, uint16_t jsonTemplateSize,
                                                        uint16_t *jsonTemplateLen, uint16_t address_len, char *address,
                                                        chunk_t *chunks) {
    char namespace_and_module[30] = {0};
    if (chunks[NAMESPACE_POS].len > 0 && chunks[MODULE_POS].len > 0) {
        snprintf(namespace_and_module, sizeof(namespace_and_module), "%.*s.%.*s", chunks[NAMESPACE_POS].len,
                 chunks[NAMESPACE_POS].data, chunks[MODULE_POS].len, chunks[MODULE_POS].data);
    } else {
        snprintf(namespace_and_module, sizeof(namespace_and_module), "%s", "coin");
    }
#if !defined(TARGET_NANOS)
    snprintf(jsonTemplate, jsonTemplateSize, TRANSFER_CROSSCHAIN_FORMAT, chunks[NETWORK_POS].len, chunks[NETWORK_POS].data,
             chunks[RECIPIENT_POS].len, chunks[RECIPIENT_POS].data, (int)strlen(namespace_and_module), namespace_and_module,
             address_len, address, chunks[RECIPIENT_POS].len, chunks[RECIPIENT_POS].data, chunks[RECIPIENT_CHAIN_POS].len,
             chunks[RECIPIENT_CHAIN_POS].data, chunks[AMOUNT_POS].len, chunks[AMOUNT_POS].data, address_len, address,
             address_len, address, chunks[RECIPIENT_POS].len, chunks[RECIPIENT_POS].data, chunks[AMOUNT_POS].len,
             chunks[AMOUNT_POS].data, chunks[RECIPIENT_CHAIN_POS].len, chunks[RECIPIENT_CHAIN_POS].data,
             (int)strlen(namespace_and_module), namespace_and_module, chunks[CREATION_TIME_POS].len,
             chunks[CREATION_TIME_POS].data, chunks[TTL_POS].len, chunks[TTL_POS].data, chunks[GAS_LIMIT_POS].len,
             chunks[GAS_LIMIT_POS].data, chunks[CHAIN_ID_POS].len, chunks[CHAIN_ID_POS].data, chunks[GAS_PRICE_POS].len,
             chunks[GAS_PRICE_POS].data, address_len, address, chunks[NONCE_POS].len, chunks[NONCE_POS].data);

    *jsonTemplateLen = strlen(jsonTemplate);
#else
    // For nanoS we need to use flash memory for the json template
    char *ptr = jsonTemplate;

    MEMCPY_NV((void *)ptr, (void *)"{\"networkId\":\"", 14);
    INCREMENT_POINTER_NVM(14)
    MEMCPY_NV((void *)ptr, chunks[NETWORK_POS].data, chunks[NETWORK_POS].len);
    INCREMENT_POINTER_NVM(chunks[NETWORK_POS].len)
    MEMCPY_NV((void *)ptr, (void *)"\",\"payload\":{\"exec\":{\"data\":{\"ks\":{\"pred\":\"keys-all\",\"keys\":[\"", 62);
    INCREMENT_POINTER_NVM(62)
    MEMCPY_NV((void *)ptr, chunks[RECIPIENT_POS].data, chunks[RECIPIENT_POS].len);
    INCREMENT_POINTER_NVM(chunks[RECIPIENT_POS].len)
    MEMCPY_NV((void *)ptr, (void *)"\"]}},\"code\":\"(", 14);
    INCREMENT_POINTER_NVM(14)
    MEMCPY_NV((void *)ptr, namespace_and_module, strlen(namespace_and_module));
    INCREMENT_POINTER_NVM(strlen(namespace_and_module))
    MEMCPY_NV((void *)ptr, (void *)".transfer-crosschain \\\"k:", 25);
    INCREMENT_POINTER_NVM(25)
    MEMCPY_NV((void *)ptr, address, address_len);
    INCREMENT_POINTER_NVM(address_len)
    MEMCPY_NV((void *)ptr, (void *)"\\\" \\\"k:", 7);
    INCREMENT_POINTER_NVM(7)
    MEMCPY_NV((void *)ptr, chunks[RECIPIENT_POS].data, chunks[RECIPIENT_POS].len);
    INCREMENT_POINTER_NVM(chunks[RECIPIENT_POS].len)
    MEMCPY_NV((void *)ptr, (void *)"\\\" (read-keyset \\\"ks\\\") \\\"", 26);
    INCREMENT_POINTER_NVM(26)
    MEMCPY_NV((void *)ptr, chunks[RECIPIENT_CHAIN_POS].data, chunks[RECIPIENT_CHAIN_POS].len);
    INCREMENT_POINTER_NVM(chunks[RECIPIENT_CHAIN_POS].len)
    MEMCPY_NV((void *)ptr, (void *)"\\\" ", 3);
    INCREMENT_POINTER_NVM(3)
    MEMCPY_NV((void *)ptr, chunks[AMOUNT_POS].data, chunks[AMOUNT_POS].len);
    INCREMENT_POINTER_NVM(chunks[AMOUNT_POS].len)
    MEMCPY_NV((void *)ptr, (void *)")\"}},\"signers\":[{\"pubKey\":\"", 27);
    INCREMENT_POINTER_NVM(27)
    MEMCPY_NV((void *)ptr, address, address_len);
    INCREMENT_POINTER_NVM(address_len)
    MEMCPY_NV((void *)ptr, (void *)"\",\"clist\":[{\"args\":[\"k:", 23);
    INCREMENT_POINTER_NVM(23)
    MEMCPY_NV((void *)ptr, address, address_len);
    INCREMENT_POINTER_NVM(address_len)
    MEMCPY_NV((void *)ptr, (void *)"\",\"k:", 5);
    INCREMENT_POINTER_NVM(5)
    MEMCPY_NV((void *)ptr, chunks[RECIPIENT_POS].data, chunks[RECIPIENT_POS].len);
    INCREMENT_POINTER_NVM(chunks[RECIPIENT_POS].len)
    MEMCPY_NV((void *)ptr, (void *)"\",", 2);
    INCREMENT_POINTER_NVM(2)
    MEMCPY_NV((void *)ptr, chunks[AMOUNT_POS].data, chunks[AMOUNT_POS].len);
    INCREMENT_POINTER_NVM(chunks[AMOUNT_POS].len)
    MEMCPY_NV((void *)ptr, (void *)",\"", 2);
    INCREMENT_POINTER_NVM(2)
    MEMCPY_NV((void *)ptr, chunks[RECIPIENT_CHAIN_POS].data, chunks[RECIPIENT_CHAIN_POS].len);
    INCREMENT_POINTER_NVM(chunks[RECIPIENT_CHAIN_POS].len)
    MEMCPY_NV((void *)ptr, (void *)"\"],\"name\":\"", 11);
    INCREMENT_POINTER_NVM(11)
    MEMCPY_NV((void *)ptr, namespace_and_module, strlen(namespace_and_module));
    INCREMENT_POINTER_NVM(strlen(namespace_and_module))
    MEMCPY_NV((void *)ptr,
              (void *)".TRANSFER_XCHAIN\"},{\"args\":[],\"name\":\"coin.GAS\"}]}],\"meta\":{\"creationTime\":", 75);
    INCREMENT_POINTER_NVM(75)
    MEMCPY_NV((void *)ptr, chunks[CREATION_TIME_POS].data, chunks[CREATION_TIME_POS].len);
    INCREMENT_POINTER_NVM(chunks[CREATION_TIME_POS].len)
    MEMCPY_NV((void *)ptr, (void *)",\"ttl\":", 7);
    INCREMENT_POINTER_NVM(7)
    MEMCPY_NV((void *)ptr, chunks[TTL_POS].data, chunks[TTL_POS].len);
    INCREMENT_POINTER_NVM(chunks[TTL_POS].len)
    MEMCPY_NV((void *)ptr, (void *)",\"gasLimit\":", 12);
    INCREMENT_POINTER_NVM(12)
    MEMCPY_NV((void *)ptr, chunks[GAS_LIMIT_POS].data, chunks[GAS_LIMIT_POS].len);
    INCREMENT_POINTER_NVM(chunks[GAS_LIMIT_POS].len)
    MEMCPY_NV((void *)ptr, (void *)",\"chainId\":\"", 12);
    INCREMENT_POINTER_NVM(12)
    MEMCPY_NV((void *)ptr, chunks[CHAIN_ID_POS].data, chunks[CHAIN_ID_POS].len);
    INCREMENT_POINTER_NVM(chunks[CHAIN_ID_POS].len)
    MEMCPY_NV((void *)ptr, (void *)"\",\"gasPrice\":", 13);
    INCREMENT_POINTER_NVM(13)
    MEMCPY_NV((void *)ptr, chunks[GAS_PRICE_POS].data, chunks[GAS_PRICE_POS].len);
    INCREMENT_POINTER_NVM(chunks[GAS_PRICE_POS].len)
    MEMCPY_NV((void *)ptr, (void *)",\"sender\":\"k:", 13);
    INCREMENT_POINTER_NVM(13)
    MEMCPY_NV((void *)ptr, address, address_len);
    INCREMENT_POINTER_NVM(address_len)
    MEMCPY_NV((void *)ptr, (void *)"\"},\"nonce\":\"", 12);
    INCREMENT_POINTER_NVM(12)
    MEMCPY_NV((void *)ptr, chunks[NONCE_POS].data, chunks[NONCE_POS].len);
    INCREMENT_POINTER_NVM(chunks[NONCE_POS].len)
    MEMCPY_NV((void *)ptr, (void *)"\"}", 2);
    INCREMENT_POINTER_NVM(2)

    *jsonTemplateLen = ptr - jsonTemplate;
#endif

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
