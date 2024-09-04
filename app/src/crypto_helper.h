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

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <sigutils.h>
#include <stdbool.h>
#include <zxmacros.h>

#include "coin.h"
#include "zxerror.h"

#if defined(TARGET_NANOS) || defined(TARGET_NANOX) || defined(TARGET_NANOS2) || defined(TARGET_STAX) || defined(TARGET_FLEX)
// blake2 needs to define output size in bits 512 bits = 64 bytes
#define BLAKE2B_OUTPUT_LEN 256
#else
#define BLAKE2B_OUTPUT_LEN 32
#endif

#define BLAKE2B_HASH_SIZE 32

zxerr_t blake2b_hash(const unsigned char *in, unsigned int inLen, unsigned char *out);
zxerr_t blake2b_incremental(const unsigned char *in, unsigned int inLen, unsigned char *out, bool isNew, bool isLast);
#ifdef __cplusplus
}
#endif
