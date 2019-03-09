/*
 * MIT License
 *
 * Copyright (c) 2019 Francesco Lavra <francescolavra.fl@gmail.com>
 * and Contributors
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#ifndef _IOTA_COMMON_H_
#define _IOTA_COMMON_H_

#include <stdint.h>

#define IOTA_OK					0
#define IOTA_ERR_INV_ADDR		-1
#define IOTA_ERR_INV_TAG		-2
#define IOTA_ERR_NETWORK		-3
#define IOTA_ERR_FRAGM_BALANCE	-4
#define IOTA_ERR_INSUFF_BALANCE	-5
#define IOTA_ERR_POW			-6
#define IOTA_ERR_NO_MEM			-7
#define IOTA_ERR_INV_SEED		-8
#define IOTA_ERR_INV_MSG		-9
#define IOTA_ERR_INTERNAL		-10

typedef struct iota_hash_s {
	char str[81 + 1];
} iota_hash_t;

typedef struct iota_addr_s {
	char str[81 + 9 + 1];
} iota_addr_t;

typedef struct iota_tag_s {
	char str[27 + 1];
} iota_tag_t;

typedef struct iota_nonce_s {
	char str[27 + 1];
} iota_nonce_t;

typedef struct iota_tx_raw_s {
	char str[2673 + 1];
} iota_tx_raw_t;

struct iota_tx {
	char sig_or_msg[2187 + 1];
	iota_addr_t address;
	int64_t value;
	iota_tag_t obsoleteTag;
	iota_tag_t tag;
	int64_t timestamp;
	int64_t currentIndex;
	int64_t lastIndex;
	iota_hash_t bundle;
	iota_hash_t trunk;
	iota_hash_t branch;
	int64_t attachmentTimestamp;
	int64_t attachmentTimestampLowerBound;
	int64_t attachmentTimestampUpperBound;
	iota_nonce_t nonce;
};

/** Verify address checksum for correctness
  @param addr  Address (with appended 9-tryte checksum) whose checksum has
         to be verified
  @return 0 if checksum is correct, negative number otherwise
*/
int iota_addr_verify_cksum(const iota_addr_t *addr);

/** Parse IOTA transaction
  @param tx_chars  Transaction trytes
  @param tx  Pointer to variable where parsed transaction is stored
  @return none
*/
void iota_tx_parse(const char *tx_chars, struct iota_tx *tx);

/** Retrieve IOTA amount in transaction
  @param tx  Transaction
  @return IOTA amount
*/
int64_t iota_tx_get_value(iota_tx_raw_t *tx);

/** Retrieve address in transaction
  @param tx  Transaction
  @param addr  Pointer to variable where address is stored
  @return none
*/
void iota_tx_get_addr(iota_tx_raw_t *tx, iota_addr_t *addr);

#endif
