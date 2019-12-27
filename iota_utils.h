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

#ifndef _IOTA_UTILS_H_
#define _IOTA_UTILS_H_

#include "iota_common.h"

#include "iota-c-library/src/iota/transfers.h"

struct iota_bundle {
	iota_wallet_bundle_description_t descr;
	iota_hash_t bundle_hash;
	iota_tx_raw_t *txs;
};

struct iota_bundle *iota_alloc_bundle(int num_outputs, int num_zero_txs,
		int num_inputs, unsigned int security, int with_change);
void iota_free_bundle(struct iota_bundle *bundle);

int iota_bundle_hash_receiver(char *hash);
int iota_tx_receiver(iota_wallet_tx_object_t *tx_object);

extern iota_tx_raw_t *iota_tx_ptr;
extern iota_hash_t *iota_bundle_hash_ptr;

#endif
