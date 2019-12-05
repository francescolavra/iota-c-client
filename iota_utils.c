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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "iota_utils.h"

#include "iota-c-library/src/iota/addresses.h"
#include "iota-c-library/src/iota/conversion.h"

#ifdef IOTAUTILS_DEBUG
#define DPRINTF	printf
#else
#define DPRINTF(fmt, ...)	do {} while(0)
#endif

#define MEMCPY_TERM(dest, src, len)   do { \
	memcpy(dest, src, len);	\
	(dest)[len] = '\0';	\
} while (0)

int iota_addr_verify_cksum(const iota_addr_t *addr)
{
	return (address_verify_checksum(addr->str));
}

void iota_tx_parse(const char *tx_chars, struct iota_tx *tx)
{
	MEMCPY_TERM(tx->sig_or_msg, &tx_chars[0], NUM_SIG_MSG_TRYTES);
	MEMCPY_TERM(tx->address.str, &tx_chars[2187], NUM_ADDR_TRYTES);
	chars_to_int64(&tx_chars[2268], &tx->value, 27);
	MEMCPY_TERM(tx->obsoleteTag.str, &tx_chars[2295], NUM_TAG_TRYTES);
	chars_to_int64(&tx_chars[2322], &tx->timestamp, 9);
	chars_to_int64(&tx_chars[2331], &tx->currentIndex, 9);
	chars_to_int64(&tx_chars[2340], &tx->lastIndex, 9);
	MEMCPY_TERM(tx->bundle.str, &tx_chars[2349], NUM_HASH_TRYTES);
	MEMCPY_TERM(tx->trunk.str, &tx_chars[2430], NUM_HASH_TRYTES);
	MEMCPY_TERM(tx->branch.str, &tx_chars[2511], NUM_HASH_TRYTES);
	MEMCPY_TERM(tx->tag.str, &tx_chars[2592], NUM_TAG_TRYTES);
	chars_to_int64(&tx_chars[2619], &tx->attachmentTimestamp, 9);
	chars_to_int64(&tx_chars[2628], &tx->attachmentTimestampLowerBound, 9);
	chars_to_int64(&tx_chars[2637], &tx->attachmentTimestampUpperBound, 9);
	MEMCPY_TERM(tx->nonce.str, &tx_chars[2646], NUM_NONCE_TRYTES);
}

int64_t iota_tx_get_value(iota_tx_raw_t *tx)
{
	int64_t value;

	chars_to_int64(&tx->str[2268], &value, 27);
	return value;
}

void iota_tx_get_addr(iota_tx_raw_t *tx, iota_addr_t *addr)
{
	MEMCPY_TERM(addr->str, &tx->str[2187], NUM_ADDR_TRYTES);
}

iota_tx_raw_t *iota_tx_ptr;
iota_hash_t *iota_bundle_hash_ptr;

struct iota_bundle *iota_alloc_bundle(int num_outputs, int num_zero_txs,
		int num_inputs, unsigned int security, int with_change)
{
	int tx_count;
	int i;
	struct iota_bundle *bundle = (struct iota_bundle *) malloc(sizeof(*bundle));

	if (!bundle) {
		DPRINTF("%s: couldn't allocate memory for bundle\n", __FUNCTION__);
		return NULL;
	}
	memset(&bundle->descr, 0, sizeof(bundle->descr));
	tx_count = num_outputs + num_zero_txs + num_inputs * security +
			!!with_change;
	bundle->txs = (iota_tx_raw_t *) malloc(sizeof(iota_tx_raw_t) * tx_count *
			2);
	if (!bundle->txs) {
		DPRINTF("%s: couldn't allocate memory for transaction characters\n",
				__FUNCTION__);
		goto error;
	}
	bundle->txs_with_pow = bundle->txs + tx_count;
	if (num_outputs > 0) {
		bundle->descr.output_txs = (iota_wallet_tx_output_t *) malloc(
				num_outputs * sizeof(iota_wallet_tx_output_t));
		if (!bundle->descr.output_txs) {
			DPRINTF("%s: couldn't allocate memory for output transactions\n",
					__FUNCTION__);
			goto error;
		}
		for (i = 0; i < num_outputs; i++) {
			memset(bundle->descr.output_txs[i].tag, '9', NUM_TAG_TRYTES);
		}
		bundle->descr.output_txs_length = num_outputs;
	}
	if (num_zero_txs > 0) {
		bundle->descr.zero_txs = (iota_wallet_tx_zero_t *) malloc(
				num_zero_txs * sizeof(iota_wallet_tx_zero_t));
		if (!bundle->descr.zero_txs) {
			DPRINTF("%s: couldn't allocate memory for 0-value transactions\n",
					__FUNCTION__);
			goto error;
		}
		for (i = 0; i < num_zero_txs; i++) {
			memset(bundle->descr.zero_txs[i].tag, '9', NUM_TAG_TRYTES);
		}
		bundle->descr.zero_txs_length = num_zero_txs;
	}
	if (num_inputs > 0) {
		bundle->descr.input_txs = (iota_wallet_tx_input_t *) malloc(
				num_inputs * sizeof(iota_wallet_tx_input_t));
		if (!bundle->descr.input_txs) {
			DPRINTF("%s: couldn't allocate memory for input transactions\n",
					__FUNCTION__);
			goto error;
		}
		bundle->descr.input_txs_length = num_inputs;
		bundle->descr.security = security;
	}
	if (with_change) {
		bundle->descr.change_tx = (iota_wallet_tx_output_t *) malloc(
				sizeof(iota_wallet_tx_output_t));
		if (!bundle->descr.change_tx) {
			DPRINTF("%s: couldn't allocate memory for change transaction\n",
					__FUNCTION__);
			goto error;
		}
		memset(bundle->descr.change_tx->tag, '9', NUM_TAG_TRYTES);
	}
	bundle->descr.timestamp = time(NULL);
	return bundle;
error:
	iota_free_bundle(bundle);
	return NULL;
}

void iota_free_bundle(struct iota_bundle *bundle)
{
	free(bundle->descr.change_tx);
	free(bundle->descr.input_txs);
	free(bundle->descr.zero_txs);
	free(bundle->descr.output_txs);
	free(bundle->txs);
	free(bundle);
}

int iota_bundle_hash_receiver(char *hash)
{
	if (iota_bundle_hash_ptr) {
		memcpy(iota_bundle_hash_ptr->str, hash, NUM_HASH_TRYTES);
		return 1;
	}
	else {
		return 0;
	}
}

int iota_tx_receiver(iota_wallet_tx_object_t *tx_object)
{
	if (iota_tx_ptr && iota_bundle_hash_ptr) {
		iota_wallet_construct_raw_transaction_chars(iota_tx_ptr->str,
				iota_bundle_hash_ptr->str, tx_object);
		iota_tx_ptr->str[NUM_TRANSACTION_TRYTES] = '\0';
		iota_tx_ptr --;
		return 1;
	}
	else {
		return 0;
	}
}
