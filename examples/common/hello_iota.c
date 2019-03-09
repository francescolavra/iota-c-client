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
#include <string.h>

#include <iota_client.h>
#include <iota_wallet.h>

#include "iota_examples.h"

static void dump_node_info() {
	struct iota_node_info node_info;

	if (iota_client_get_node_info(&node_info)) {
		printf("Couldn't get node info\n");
		return;
	}
	printf("App Name: %s\n", node_info.appName);
	printf("App Version: %s\n", node_info.appVersion);
	printf("JRE Version: %s\n", node_info.jreVersion);
	printf("Available Processors: %d\n", node_info.jreAvailableProcessors);
	printf("Free Memory: %lu\n", node_info.jreFreeMemory);
	printf("Max Memory: %lu\n", node_info.jreMaxMemory);
	printf("Total Memory: %lu\n", node_info.jreTotalMemory);
	printf("Latest Milestone: %s\n", node_info.latestMilestone.str);
	printf("Latest Milestone Index: %d\n", node_info.latestMilestoneIndex);
	printf("Latest Solid Subtangle Milestone: %s\n",
			node_info.latestSolidSubtangleMilestone.str);
	printf("Latest Solid Subtangle Milestone Index: %d\n",
			node_info.latestSolidSubtangleMilestoneIndex);
	printf("Neighbors: %d\n", node_info.neighbors);
	printf("Packet Queue Size: %d\n", node_info.packetsQueueSize);
	printf("Tips: %d\n", node_info.tips);
	printf("Transactions to Request: %d\n", node_info.transactionsToRequest);
	printf("Features:");
	for (int i = 0; i < node_info.feature_count; i++) {
		printf(" %s", node_info.features[i]);
	}
	printf("\nCoordinator Address: %s\n", node_info.coordinatorAddress.str);
}

static void dump_transaction(iota_hash_t *tx_hash) {
	struct iota_tx tx;

	if (iota_client_get_transaction(tx_hash, &tx) < 0) {
		printf("Couldn't get transaction\n");
		return;
	}
	printf("Signature or Message: %s\n", tx.sig_or_msg);
	printf("Address: %s\n", tx.address.str);
	printf("Value: %lld\n", tx.value);
	printf("Obsolete Tag: %s\n", tx.obsoleteTag.str);
	printf("Tag: %s\n", tx.tag.str);
	printf("Timestamp: %lld\n", tx.timestamp);
	printf("Current Index: %lld\n", tx.currentIndex);
	printf("Last Index: %lld\n", tx.lastIndex);
	printf("Bundle: %s\n", tx.bundle.str);
	printf("Trunk: %s\n", tx.trunk.str);
	printf("Branch: %s\n", tx.branch.str);
	printf("Attachment Timestamp: %lld\n", tx.attachmentTimestamp);
	printf("Attachment Timestamp Lower Bound: %lld\n",
			tx.attachmentTimestampLowerBound);
	printf("Attachment Timestamp Upper Bound: %lld\n",
			tx.attachmentTimestampUpperBound);
	printf("Nonce: %s\n", tx.nonce.str);
}

void hello_iota(const char *seed)
{
    static iota_addr_t addr;
	iota_hash_t bundle;
    static iota_hash_t txs[8];
    iota_tag_t tag;
	uint64_t balance;
	int ret;

	if (iota_wallet_setup(seed, "https://nodes.thetangle.org") < 0) {
		printf("Cannot initialize IOTA wallet\n");
		return;
	}
	printf("Node Info:\n");
	dump_node_info();
	printf("\n");
	ret = iota_wallet_get_balance(&balance, 0, NULL);
	if (ret == 0) {
		printf("IOTA balance %llu\n", balance);
	}
	else {
		printf("Couldn't get IOTA balance\n");
	}
	printf("Generating addresses from seed:\n");
	for (int index = 0; index < 10; index++) {
		iota_wallet_get_addr(&addr, index, 1);
		printf("  index %d: %s\n", index, addr.str);
	}
	printf("Retrieving transactions in a bundle...\n");
	strcpy(bundle.str,
			"GLATHXDGQATTHDXRPJUPFXYJK9VFPIBXZJCZYIKYYRYV9ZBPHCPLV9BCZTCYUBLKKZDHUAYCQC9OIVRCZ");
	ret = iota_client_find_transactions(txs, 8, &bundle, 1, NULL, 0, NULL, 0,
			NULL, 0);
	if (ret >= 0) {
		printf("Found %d transaction(s)\n", ret);
		if (ret > 0) {
			iota_hash_t *last_tx = &txs[ret - 1];

			printf("Last Transaction (%s):\n", last_tx->str);
			dump_transaction(last_tx);
		}
	}
	else {
		printf("Couldn't find transactions\n");
	}
	printf("\nSending message (0-value transaction)...\n");
	sprintf(addr.str,
			"IOTAADDRESSIOTAADDRESSIOTAADDRESSIOTAADDRESSIOTAADDRESSIOTAADDRESSIOTAADDRESS9999ZOKRYDMKZ");
	sprintf(tag.str, "TAGTAGTAGTAGTAGTAGTAGTAGTAG");
	ret = iota_client_send_msg(
			"HELLO9FROM9IOTA9CLIENT", &addr, &tag);
	printf("Result: %d (%s)\n", ret, (ret == IOTA_OK) ? "OK" : "error");
}
