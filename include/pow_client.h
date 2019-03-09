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

#ifndef _POW_CLIENT_H_
#define _POW_CLIENT_H_

#include "iota_common.h"

/** Perform Proof of Work on a transaction bundle
  @param priv  Pointer to PoW client private data
  @param trunk  Hash of trunk transaction to be approved when attaching
         transactions to the tangle
  @param branch  Hash of branch transaction to be approved when attaching
         transactions to the tangle
  @param mwm  Minimum weight magnitude to be used when doing Proof of Work
  @param txs  Array of transactions constituting the bundle on which Proof of
         Work should be performed
  @param tx_count  Number of transactions in the bundle
  @param txs_with_pow  Array that is filled with transaction data with Proof of
         Work
  @return 0 if Proof of Work has been done successfully, negative number
          otherwise
	*/
typedef int (*pow_handler_t)(void *priv, iota_hash_t *trunk,
		iota_hash_t *branch, int mwm, iota_tx_raw_t *txs, unsigned int tx_count,
		iota_tx_raw_t *txs_with_pow);

#endif
