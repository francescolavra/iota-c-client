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

#ifndef _IOTA_CLIENT_H_
#define _IOTA_CLIENT_H_

#include <stdint.h>

#include "iota_common.h"
#include "pow_client.h"

struct iota_node_info {
	char appName[32];
	char appVersion[32];
	char jreVersion[32];
	int jreAvailableProcessors;
	unsigned long long jreFreeMemory;
	unsigned long long jreMaxMemory;
	unsigned long long jreTotalMemory;
	iota_hash_t latestMilestone;
	int latestMilestoneIndex;
	iota_hash_t latestSolidSubtangleMilestone;
	int latestSolidSubtangleMilestoneIndex;
	int neighbors;
	int packetsQueueSize;
	int tips;
	int transactionsToRequest;
	char features[8][32];
	int feature_count;
	iota_addr_t coordinatorAddress;
};

/** Initialize IOTA client
  @param node_url  URL used to communicate with full IOTA node
  @return 0 if successful, negative number otherwise
*/
int iota_client_init(const char *node_url);

/** Retrieve node information from remote IOTA node
  @param info  Pointer to node information structure that is filled with
         data received from the remote node
  @return 0 if successful, negative number otherwise
*/
int iota_client_get_node_info(struct iota_node_info *info);

/** Retrieve balance of a list of addresses
  @param addrs  Array of addresses for which the balance must be retrieved
  @param addr_count  Length of address array
  @param balances  Array that is filled with balance values (one value for
         each address)
  @return 0 if successful, negative number otherwise
*/
int iota_client_get_balances(iota_addr_t *addrs, unsigned int addr_count,
		uint64_t *balances);

/** Find transactions that match a set of criteria
  @param txs  Array that is filled with hashes of retrieved transactions
  @param tx_limit  Length of transaction array, i.e. maximum number of
         transactions to be retrieved
  @param bundles  Array of hashes of bundles to which transactions must
         belong; if NULL, transactions can belong to any bundle
  @param bundle_count  Length of bundle array; if 0, transactions can belong to
         any bundle
  @param addrs  Array of addresses that must be contained in transactions; if
         NULL, transactions can contain any address
  @param addr_count  Length of address array; if 0, transactions can contain any
         address
  @param tags  Array of tags that must be contained in transactions; if NULL,
         transactions can contain any tag
  @param tag_count  Length of tag array; if 0, transactions can contain any tag
  @param approvees  Array of hashes of transactions that must be approved from
         the transactions to be retrieved; if NULL, transactions can approve any
         transaction
  @param approvee_count  Length of approvee array; if 0, transactions can
         approve any transaction
  @return number of found transactions if successful, negative number otherwise
*/
int iota_client_find_transactions(iota_hash_t *txs, unsigned int tx_limit,
		iota_hash_t *bundles, unsigned int bundle_count,
		iota_addr_t *addrs, unsigned int addr_count,
		iota_tag_t *tags, unsigned int tag_count,
		iota_hash_t *approvees, unsigned int approvee_count);

/** Retrieve transaction data from a given transaction hash
  @param hash  Transaction hash
  @param tx  Pointer to structure that is filled with transaction data
         retrieved from the remote node
  @return 0 if successful, negative number otherwise
*/
int iota_client_get_transaction(iota_hash_t *hash, struct iota_tx *tx);

/** Retrieve two transactions to be approved (tips) in the tangle
  @param depth  Random walk depth for the tip selection process
  @param trunk  Pointer to variable that will contain the hash of the first
         transaction to be approved
  @param branch  Pointer to variable that will contain the hash of the
         second transaction to be approved
  @return 0 if successful, negative number otherwise
*/
int iota_client_get_transactions_to_approve(int depth, iota_hash_t *trunk,
		iota_hash_t *branch);

/** Attach bundle of transactions to the tangle, by doing Proof of Work
  @param trunk  Hash of trunk transaction to be approved when attaching
         transactions to the tangle; it can be retrieved via the
         getTransactionsToApprove() method
  @param branch  Hash of branch transaction to be approved when attaching
         transactions to the tangle; it can be retrieved via the
         getTransactionsToApprove() method
  @param mwm  Minimum weight magnitude to be used when doing Proof of Work
  @param txs  Array of transactions to attach to the tangle as a bundle; these
         transactions are modified inside this function by adding Proof of Work
         data received from the remote node
  @param tx_count  Length of transaction array
  @return 0 if successful, negative number otherwise
*/
int iota_client_attach_to_tangle(iota_hash_t *trunk, iota_hash_t *branch,
		int mwm, iota_tx_raw_t *txs, unsigned int tx_count);

/** Store transactions in the tangle
  @param txs  Array of transactions (with Proof of Work) to be stored in the
         tangle; transactions can be retrieved via the attachToTangle() method
  @param tx_count  Length of transaction array
  @return 0 if successful, negative number otherwise
*/
int iota_client_store_transactions(iota_tx_raw_t *txs, unsigned int tx_count);

/** Broadcast transactions to neighbor nodes
  @param txs  Array of transactions (with Proof of Work) to be broadcast to
         neighbors; transactions can be retrieved via the attachToTangle()
         method
  @param tx_count  Length of transaction array
  @return 0 if successful, negative number otherwise
*/
int iota_client_broadcast_transactions(iota_tx_raw_t *txs,
		unsigned int tx_count);

/** Check if IOTA addresses have been spent from
  @param addrs  Array of addresses for which the check must be executed
  @param addr_count  Length of address array
  @param spent  Array that will be filled with values (one for each address
         supplied in the first argument) that indicate whether the addresses
         have been spent from (non-zero value means spent)
  @return 0 if successful, negative number otherwise
*/
int iota_client_were_addresses_spent_from(iota_addr_t *addrs,
		unsigned int addr_count, int *spent);

/** Retrieve current minimum weight magnitude
  The minimum weight magnitude is an integer number used to perform Proof of
  Work when attaching transactions to the tangle.
  @return current minimum weight magnitude
*/
unsigned int iota_client_get_mwm(void);

/** Configure minimum weight magnitude
  The minimum weight magnitude is an integer number used to perform Proof of
  Work when attaching transactions to the tangle.
  @param mwm  Minimum weight magnitude
  @return none
*/
void iota_client_set_mwm(unsigned int mwm);

/** Configure Proof of Work handler
  By default, Proof of Work is done by calling the attachToTangle API on the
  IOTA node to which the IOTA client is connected. With this function it is
  possible to perform Proof-of-Work by other means using a custom
  implementation.
  @param handler  Function that will be called to perform Proof of Work instead
         of using the attachToTangle API
  @param priv  Pointer to Proof of Work handler private data, to be passed to
         handler function
  @return none
*/
void iota_client_set_pow_handler(pow_handler_t handler, void *priv);

/** Send message to IOTA address
  This function works by creating a bundle consisting of one or more 0-valued
  transactions.
  @param msg  Message to be sent, expressed as a NULL-terminated string of
         trytes
  @param address  Address to be put in transaction(s), with or without checksum
         appended
  @param tag  Transaction tag (up to 27 trytes); can be NULL, in which case a
         default tag is used
  @return 0 if successful, negative number otherwise
*/
int iota_client_send_msg(const char *msg, const iota_addr_t *address,
		const iota_tag_t *tag);

/** Attach an address to the tangle
  This function creates a zero-valued IOTA transaction with the specified
  address and attaches it to the tangle by doing Proof of Work.
  @param addr  Address to be attached to the tangle (the address checksum is
         not necessary)
  @return 0 if communication with the IOTA full node is successful, negative
          number otherwise
*/
int iota_client_attach_address(const iota_addr_t *addr);

#endif
