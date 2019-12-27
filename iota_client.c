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

#include <string.h>

#include "iota_client.h"
#include "iota_common.h"
#include "iota_utils.h"
#include "platform.h"

#include "iota-c-library/src/iota/addresses.h"
#include "iota-c-library/src/iota/bundle.h"
#include "iota-c-library/src/iota/conversion.h"

#define IOTACLIENT_RANDOMWALK_DEPTH	3

#ifdef IOTACLIENT_DEBUG
#define DPRINTF	printf
#else
#define DPRINTF(fmt, ...)	do {} while(0)
#endif

static struct {
	void *http_client;
	unsigned int mwm;
	pow_handler_t pow_handler;
	void *pow_priv;
} iota_client;

static int json_get_int(cJSON *obj, const char *name, int *dest)
{
	cJSON *attr = cJSON_GetObjectItem(obj, name);

	if (!attr || !cJSON_IsNumber(attr)) {
		return -1;
	}
	*dest = attr->valuedouble;
	return 0;
}

static int json_get_ulonglong(cJSON *obj, const char *name,
		unsigned long long *dest)
{
	cJSON *attr = cJSON_GetObjectItem(obj, name);

	if (!attr || !cJSON_IsNumber(attr)) {
		return -1;
	}
	*dest = attr->valuedouble;
	return 0;
}

static int json_get_string(cJSON *obj, const char *name,
		char *dest, unsigned int dest_len)
{
	cJSON *attr = cJSON_GetObjectItem(obj, name);
	char *str;

	if (!attr) {
		return -1;
	}
	str = cJSON_GetStringValue(attr);
	if (!str) {
		return -1;
	}
	strncpy(dest, str, dest_len - 1);
	dest[dest_len - 1] = '\0';
	return 0;
}

static int iota_client_send_txs(const char *cmd, iota_tx_raw_t *txs,
		unsigned int tx_count)
{
	cJSON *json_req, *json_resp;
	cJSON *tx_array;
	int i;
	int ret = IOTA_OK, resp_status;

	json_req = cJSON_CreateObject();
	cJSON_AddItemToObject(json_req, "command",
			cJSON_CreateStringReference(cmd));
	tx_array = cJSON_CreateArray();
	for (i = 0; i < tx_count; i++) {
		cJSON_AddItemToArray(tx_array, cJSON_CreateStringReference(txs[i].str));
	}
	cJSON_AddItemToObject(json_req, "trytes", tx_array);
	json_resp = iota_client_send_req(iota_client.http_client, json_req,
			&resp_status);
	cJSON_Delete(json_req);
	if (!json_resp) {
		return IOTA_ERR_NETWORK;
	}
	if (resp_status != 200) {
		DPRINTF("%s: response status code %d\n", __FUNCTION__, resp_status);
		ret = IOTA_ERR_NETWORK;
	}
	cJSON_Delete(json_resp);
	return ret;
}

int iota_client_init(const char *node_url)
{
	iota_client.http_client = iota_client_http_init(node_url);
	if (iota_client.http_client == NULL) {
		DPRINTF("%s: failed to initialize HTTP client\n", __FUNCTION__);
		return -1;
	}
	iota_client.mwm = 14;
	iota_client.pow_handler = NULL;
	return 0;
}

int iota_client_get_node_info(struct iota_node_info *info)
{
	cJSON *json_req, *json_resp;
	int ret = IOTA_OK, resp_status;
	cJSON *attr;

	json_req = cJSON_CreateObject();
	cJSON_AddItemToObject(json_req, "command",
			cJSON_CreateStringReference("getNodeInfo"));
	json_resp = iota_client_send_req(iota_client.http_client, json_req,
			&resp_status);
	cJSON_Delete(json_req);
	if (!json_resp) {
		return IOTA_ERR_NETWORK;
	}
	if (resp_status != 200) {
		DPRINTF("%s: response status code %d\n", __FUNCTION__, resp_status);
		ret = IOTA_ERR_NETWORK;
		goto exit;
	}
	if (json_get_string(json_resp, "appName", info->appName,
			sizeof(info->appName)) < 0) {
		info->appName[0] = '\0';
	}
	if (json_get_string(json_resp, "appVersion", info->appVersion,
			sizeof(info->appVersion)) < 0) {
		info->appVersion[0] = '\0';
	}
	if (json_get_string(json_resp, "jreVersion", info->jreVersion,
			sizeof(info->jreVersion)) < 0) {
		info->jreVersion[0] = '\0';
	}
	if (json_get_int(json_resp, "jreAvailableProcessors",
			&info->jreAvailableProcessors) < 0) {
		info->jreAvailableProcessors = 0;
	}
	if (json_get_ulonglong(json_resp, "jreFreeMemory", &info->jreFreeMemory) <
			0) {
		info->jreFreeMemory = 0;
	}
	if (json_get_ulonglong(json_resp, "jreMaxMemory", &info->jreMaxMemory) < 0)
	{
		info->jreMaxMemory = 0;
	}
	if (json_get_ulonglong(json_resp, "jreTotalMemory", &info->jreTotalMemory) <
			0) {
		info->jreTotalMemory = 0;
	}
	if (json_get_string(json_resp, "latestMilestone", info->latestMilestone.str,
			sizeof(info->latestMilestone.str)) < 0) {
		info->latestMilestone.str[0] = '\0';
	}
	if (json_get_int(json_resp, "latestMilestoneIndex",
			&info->latestMilestoneIndex) < 0) {
		info->latestMilestoneIndex = 0;
	}
	if (json_get_string(json_resp, "latestSolidSubtangleMilestone",
			info->latestSolidSubtangleMilestone.str,
			sizeof(info->latestSolidSubtangleMilestone.str)) < 0) {
		info->latestSolidSubtangleMilestone.str[0] = '\0';
	}
	if (json_get_int(json_resp, "latestSolidSubtangleMilestoneIndex",
			&info->latestSolidSubtangleMilestoneIndex) < 0) {
		info->latestSolidSubtangleMilestoneIndex = 0;
	}
	if (json_get_int(json_resp, "neighbors", &info->neighbors) < 0) {
		info->neighbors = 0;
	}
	if (json_get_int(json_resp, "packetsQueueSize", &info->packetsQueueSize)
			< 0) {
		info->packetsQueueSize = 0;
	}
	if (json_get_int(json_resp, "tips", &info->tips) < 0) {
		info->tips = 0;
	}
	if (json_get_int(json_resp, "transactionsToRequest",
			&info->transactionsToRequest) < 0) {
		info->transactionsToRequest = 0;
	}
	if (json_get_string(json_resp, "coordinatorAddress",
			info->coordinatorAddress.str, sizeof(info->coordinatorAddress.str))
			< 0) {
		info->coordinatorAddress.str[0] = '\0';
	}
	info->feature_count = 0;
	attr = cJSON_GetObjectItem(json_resp, "features");
	if (cJSON_IsArray(attr)) {
		cJSON *featureObj;
		char *feature;

		cJSON_ArrayForEach(featureObj, attr) {
			feature = cJSON_GetStringValue(featureObj);
			if (!feature) {
				continue;
			}
			strncpy(info->features[info->feature_count], feature,
					sizeof(info->features[info->feature_count]) - 1);
			info->features[info->feature_count]
				   [sizeof(info->features[info->feature_count]) - 1] = '\0';
			if (++info->feature_count ==
					sizeof(info->features) / sizeof(info->features[0])) {
				break;
			}
		}
	}
exit:
	cJSON_Delete(json_resp);
	return ret;
}

int iota_client_get_balances(iota_addr_t *addrs, unsigned int addr_count,
		uint64_t *balances)
{
	cJSON *json_req, *json_resp, *addr_array;
	int i;
	int ret = IOTA_OK, resp_status;
	cJSON *attr;

	json_req = cJSON_CreateObject();
	cJSON_AddItemToObject(json_req, "command",
			cJSON_CreateStringReference("getBalances"));
	addr_array = cJSON_CreateArray();
	for (i = 0; i < addr_count; i++) {
		cJSON_AddItemToArray(addr_array,
				cJSON_CreateStringReference(addrs[i].str));
	}
	cJSON_AddItemToObject(json_req, "addresses", addr_array);
	cJSON_AddItemToObject(json_req, "threshold", cJSON_CreateNumber(100));
	json_resp = iota_client_send_req(iota_client.http_client, json_req,
			&resp_status);
	cJSON_Delete(json_req);
	if (!json_resp) {
		return IOTA_ERR_NETWORK;
	}
	if (resp_status != 200) {
		DPRINTF("%s: response status code %d\n", __FUNCTION__, resp_status);
		ret = IOTA_ERR_NETWORK;
		goto exit;
	}
	attr = cJSON_GetObjectItem(json_resp, "balances");
	if (cJSON_IsArray(attr) && (cJSON_GetArraySize(attr) == addr_count)) {
		cJSON *balance_obj;
		char *balance_str;

		addr_count = 0;
		cJSON_ArrayForEach(balance_obj, attr) {
			balance_str = cJSON_GetStringValue(balance_obj);
			if (!balance_str) {
				ret = IOTA_ERR_NETWORK;
				break;
			}
			balances[addr_count++] = strtoull(balance_str, NULL, 10);
		}
	}
	else {
		ret = IOTA_ERR_NETWORK;
	}
exit:
	cJSON_Delete(json_resp);
	return ret;
}

int iota_client_find_transactions(iota_hash_t *txs, unsigned int tx_limit,
		iota_hash_t *bundles, unsigned int bundle_count,
		iota_addr_t *addrs, unsigned int addr_count,
		iota_tag_t *tags, unsigned int tag_count,
		iota_hash_t *approvees, unsigned int approvee_count)
{
	cJSON *json_req, *json_resp;
	int i;
	int ret = IOTA_OK, resp_status;
	cJSON *attr;

	json_req = cJSON_CreateObject();
	cJSON_AddItemToObject(json_req, "command",
			cJSON_CreateStringReference("findTransactions"));
	if (bundle_count != 0) {
		cJSON *bundle_array = cJSON_CreateArray();

		for (i = 0; i < bundle_count; i++) {
			cJSON_AddItemToArray(bundle_array,
					cJSON_CreateStringReference(bundles[i].str));
		}
		cJSON_AddItemToObject(json_req, "bundles", bundle_array);
	}
	if (addr_count != 0) {
		cJSON *addr_array = cJSON_CreateArray();

		for (i = 0; i < addr_count; i++) {
			cJSON_AddItemToArray(addr_array,
					cJSON_CreateStringReference(addrs[i].str));
		}
		cJSON_AddItemToObject(json_req, "addresses", addr_array);
	}
	if (tag_count != 0) {
		cJSON *tag_array = cJSON_CreateArray();

		for (i = 0; i < tag_count; i++) {
			cJSON_AddItemToArray(tag_array,
					cJSON_CreateStringReference(tags[i].str));
		}
		cJSON_AddItemToObject(json_req, "tags", tag_array);
	}
	if (approvee_count != 0) {
		cJSON *approvee_array = cJSON_CreateArray();

		for (i = 0; i < approvee_count; i++) {
			cJSON_AddItemToArray(approvee_array,
					cJSON_CreateStringReference(approvees[i].str));
		}
		cJSON_AddItemToObject(json_req, "approvees", approvee_array);
	}
	json_resp = iota_client_send_req(iota_client.http_client, json_req,
			&resp_status);
	cJSON_Delete(json_req);
	if (!json_resp) {
		return IOTA_ERR_NETWORK;
	}
	if (resp_status != 200) {
		DPRINTF("%s: response status code %d\n", __FUNCTION__, resp_status);
		ret = IOTA_ERR_NETWORK;
		goto exit;
	}
	attr = cJSON_GetObjectItem(json_resp, "hashes");
	if (cJSON_IsArray(attr)) {
		cJSON *tx_obj;
		char *tx;

		cJSON_ArrayForEach(tx_obj, attr) {
			tx = cJSON_GetStringValue(tx_obj);
			if (tx && (strlen(tx) == NUM_HASH_TRYTES)) {
				strcpy(txs[ret].str, tx);
				if (++ret == tx_limit) {
					break;
				}
			}
		}
	}
exit:
	cJSON_Delete(json_resp);
	return ret;
}

int iota_client_get_transaction(iota_hash_t *hash, struct iota_tx *tx)
{
	cJSON *json_req, *json_resp, *hash_array;
	const char *hash_ptr = hash->str;
	int ret = IOTA_OK, resp_status;
	cJSON *attr;
	char *tx_chars;

	json_req = cJSON_CreateObject();
	cJSON_AddItemToObject(json_req, "command",
			cJSON_CreateStringReference("getTrytes"));
	hash_array = cJSON_CreateStringArray(&hash_ptr, 1);
	cJSON_AddItemToObject(json_req, "hashes", hash_array);
	json_resp = iota_client_send_req(iota_client.http_client, json_req,
			&resp_status);
	cJSON_Delete(json_req);
	if (!json_resp) {
		return IOTA_ERR_NETWORK;
	}
	if (resp_status != 200) {
		DPRINTF("%s: response status code %d\n", __FUNCTION__, resp_status);
		ret = IOTA_ERR_NETWORK;
		goto exit;
	}
	attr = cJSON_GetObjectItem(json_resp, "trytes");
	if (!cJSON_IsArray(attr) || (cJSON_GetArraySize(attr) != 1)) {
		DPRINTF("%s: unexpected JSON response\n", __FUNCTION__);
		ret = IOTA_ERR_NETWORK;
		goto exit;
	}
	tx_chars = cJSON_GetStringValue(cJSON_GetArrayItem(attr, 0));
	if (!tx_chars || (strlen(tx_chars) != NUM_TRANSACTION_TRYTES)) {
		DPRINTF("%s: unexpected element in 'trytes' array\n", __FUNCTION__);
		ret = IOTA_ERR_NETWORK;
		goto exit;
	}
	iota_tx_parse(tx_chars, tx);
exit:
	cJSON_Delete(json_resp);
	return ret;
}

int iota_client_get_transactions_to_approve(int depth, iota_hash_t *trunk,
		iota_hash_t *branch)
{
	cJSON *json_req, *json_resp;
	int ret = IOTA_OK, resp_status;

	json_req = cJSON_CreateObject();
	cJSON_AddItemToObject(json_req, "command",
			cJSON_CreateStringReference("getTransactionsToApprove"));
	cJSON_AddItemToObject(json_req, "depth", cJSON_CreateNumber(depth));
	json_resp = iota_client_send_req(iota_client.http_client, json_req,
			&resp_status);
	cJSON_Delete(json_req);
	if (!json_resp) {
		return IOTA_ERR_NETWORK;
	}
	if (resp_status != 200) {
		DPRINTF("%s: response status code %d\n", __FUNCTION__, resp_status);
		ret = IOTA_ERR_NETWORK;
		goto exit;
	}
	if (json_get_string(json_resp, "trunkTransaction", trunk->str,
			sizeof(trunk->str)) < 0) {
		DPRINTF("%s: couldn't get trunk transaction\n", __FUNCTION__);
		ret = IOTA_ERR_NETWORK;
		goto exit;
	}
	if (json_get_string(json_resp, "branchTransaction", branch->str,
			sizeof(branch->str)) < 0) {
		DPRINTF("%s: couldn't get branch transaction\n", __FUNCTION__);
		ret = IOTA_ERR_NETWORK;
		goto exit;
	}
exit:
	cJSON_Delete(json_resp);
	return ret;
}

int iota_client_attach_to_tangle(iota_hash_t *trunk, iota_hash_t *branch,
		int mwm, iota_tx_raw_t *txs, unsigned int tx_count)
{
	cJSON *json_req, *json_resp;
	cJSON *tx_array;
	int i;
	int ret = IOTA_OK, resp_status;
	cJSON *attr;

	json_req = cJSON_CreateObject();
	cJSON_AddItemToObject(json_req, "command",
			cJSON_CreateStringReference("attachToTangle"));
	cJSON_AddItemToObject(json_req, "trunkTransaction",
			cJSON_CreateStringReference(trunk->str));
	cJSON_AddItemToObject(json_req, "branchTransaction",
			cJSON_CreateStringReference(branch->str));
	cJSON_AddItemToObject(json_req, "minWeightMagnitude",
			cJSON_CreateNumber(mwm));
	tx_array = cJSON_CreateArray();
	for (i = 0; i < tx_count; i++) {
		cJSON_AddItemToArray(tx_array, cJSON_CreateStringReference(txs[i].str));
	}
	cJSON_AddItemToObject(json_req, "trytes", tx_array);
	json_resp = iota_client_send_req(iota_client.http_client, json_req,
			&resp_status);
	cJSON_Delete(json_req);
	if (!json_resp) {
		return IOTA_ERR_NETWORK;
	}
	if (resp_status != 200) {
		DPRINTF("%s: response status code %d\n", __FUNCTION__, resp_status);
		ret = IOTA_ERR_NETWORK;
		goto exit;
	}
	attr = cJSON_GetObjectItem(json_resp, "trytes");
	if (cJSON_IsArray(attr) && (cJSON_GetArraySize(attr) == tx_count)) {
		cJSON *tx_obj;
		char *tx;

		tx_count = 0;
		cJSON_ArrayForEach(tx_obj, attr) {
			tx = cJSON_GetStringValue(tx_obj);
			if (tx && (strlen(tx) == NUM_TRANSACTION_TRYTES)) {
				strcpy(txs[tx_count++].str, tx);
			}
		}
	}
	else {
		ret = IOTA_ERR_NETWORK;
	}
exit:
	cJSON_Delete(json_resp);
	return ret;
}

int iota_client_store_transactions(iota_tx_raw_t *txs, unsigned int tx_count)
{
	return iota_client_send_txs("storeTransactions", txs, tx_count);
}

int iota_client_broadcast_transactions(iota_tx_raw_t *txs,
		unsigned int tx_count)
{
	return iota_client_send_txs("broadcastTransactions", txs, tx_count);
}

int iota_client_were_addresses_spent_from(iota_addr_t *addrs,
		unsigned int addr_count, int *spent)
{
	cJSON *json_req, *json_resp, *addr_array;
	int i;
	int ret = IOTA_OK, resp_status;
	cJSON *attr;

	json_req = cJSON_CreateObject();
	cJSON_AddItemToObject(json_req, "command",
			cJSON_CreateStringReference("wereAddressesSpentFrom"));
	addr_array = cJSON_CreateArray();
	for (i = 0; i < addr_count; i++) {
		cJSON_AddItemToArray(addr_array,
				cJSON_CreateStringReference(addrs[i].str));
	}
	cJSON_AddItemToObject(json_req, "addresses", addr_array);
	json_resp = iota_client_send_req(iota_client.http_client, json_req,
			&resp_status);
	cJSON_Delete(json_req);
	if (!json_resp) {
		return IOTA_ERR_NETWORK;
	}
	if (resp_status != 200) {
		DPRINTF("%s: response status code %d\n", __FUNCTION__, resp_status);
		ret = IOTA_ERR_NETWORK;
		goto exit;
	}
	attr = cJSON_GetObjectItem(json_resp, "states");
	if (cJSON_IsArray(attr) && (cJSON_GetArraySize(attr) == addr_count)) {
		cJSON *stateObj;

		addr_count = 0;
		cJSON_ArrayForEach(stateObj, attr) {
			if (!cJSON_IsBool(stateObj)) {
				ret = IOTA_ERR_NETWORK;
				break;
			}
			spent[addr_count++] = cJSON_IsTrue(stateObj);
		}
	}
	else {
		ret = IOTA_ERR_NETWORK;
	}
exit:
	cJSON_Delete(json_resp);
	return ret;
}

unsigned int iota_client_get_mwm(void)
{
	return iota_client.mwm;
}

void iota_client_set_mwm(unsigned int mwm)
{
	iota_client.mwm = mwm;
}

void iota_client_set_pow_handler(pow_handler_t handler, void *priv)
{
	iota_client.pow_handler = handler;
	iota_client.pow_priv = priv;
}

int iota_client_send_msg(const char *msg, const iota_addr_t *address,
		const iota_tag_t *tag)
{
	iota_hash_t trunk, branch;
	int msg_offset, msg_len, addr_len, tag_len, tx_count;
	struct iota_bundle *bundle;
	int i;
	int ret = IOTA_OK;

	msg_len = strlen(msg);
	tx_count = msg_len / NUM_SIG_MSG_TRYTES;
	if (msg_len % NUM_SIG_MSG_TRYTES) {
		tx_count++;
	}
	if (tx_count > MAX_BUNDLE_INDEX_SZ) {
		DPRINTF("%s: message too long\n", __FUNCTION__);
		return IOTA_ERR_INV_MSG;
	}
	if (tryte_chars_validate(msg, strlen(msg)) < 0) {
		DPRINTF("%s: invalid message trytes\n", __FUNCTION__);
		return IOTA_ERR_INV_MSG;
	}
	addr_len = strlen(address->str);
	if (addr_len == NUM_ADDR_TRYTES + NUM_ADDR_CKSUM_TRYTES) {
		if (iota_addr_verify_cksum(address) < 0) {
			return IOTA_ERR_INV_ADDR;
		}
	}
	else if (addr_len != NUM_ADDR_TRYTES) {
		return IOTA_ERR_INV_ADDR;
	}
	tag_len = 0;
	if (tag) {
		tag_len = strlen(tag->str);
		if (tryte_chars_validate(tag->str, tag_len) < 0) {
			return IOTA_ERR_INV_TAG;
		}
	}
	if (iota_client_get_transactions_to_approve(IOTACLIENT_RANDOMWALK_DEPTH,
			&trunk, &branch) < 0) {
		return IOTA_ERR_NETWORK;
	}
	bundle = iota_alloc_bundle(0, tx_count, 0, 0, 0);
	if (!bundle) {
		DPRINTF("%s: couldn't allocate memory for bundle\n", __FUNCTION__);
		return IOTA_ERR_NO_MEM;
	}
	msg_offset = 0;
	for (i = 0; i < tx_count; i++) {
		if (i < tx_count - 1) {
			memcpy(bundle->descr.zero_txs[i].message, msg + msg_offset,
					NUM_SIG_MSG_TRYTES);
			msg_offset += NUM_SIG_MSG_TRYTES;
		}
		else {
			memcpy(bundle->descr.zero_txs[i].message, msg + msg_offset,
					msg_len - msg_offset);
			memset(bundle->descr.zero_txs[i].message + msg_len - msg_offset,
					'9', NUM_SIG_MSG_TRYTES - (msg_len - msg_offset));
		}
		memcpy(bundle->descr.zero_txs[i].address, address->str,
				NUM_ADDR_TRYTES);
		if (tag) {
			memcpy(bundle->descr.zero_txs[i].tag, tag->str, tag_len);
		}
	}
	iota_bundle_hash_ptr = &bundle->bundle_hash;
	iota_tx_ptr = &bundle->txs[tx_count - 1];
	iota_wallet_create_tx_bundle(iota_bundle_hash_receiver, iota_tx_receiver,
			&bundle->descr);
	if (iota_client.pow_handler) {
		DPRINTF("%s: using external PoW client\n", __FUNCTION__);
		if (iota_client.pow_handler(iota_client.pow_priv, &trunk, &branch,
				iota_client.mwm, bundle->txs, tx_count) <
		        0) {
			ret = IOTA_ERR_POW;
			goto exit;
		}
	}
	else {
		if (iota_client_attach_to_tangle(&trunk, &branch, iota_client.mwm,
				bundle->txs, tx_count) < 0) {
			ret = IOTA_ERR_NETWORK;
			goto exit;
		}
	}
	if (iota_client_store_transactions(bundle->txs, tx_count) < 0) {
		ret = IOTA_ERR_NETWORK;
		goto exit;
	}
	ret = iota_client_broadcast_transactions(bundle->txs, tx_count);
exit:
	iota_free_bundle(bundle);
	return ret;
}

int iota_client_attach_address(const iota_addr_t *addr)
{
	iota_hash_t trunk, branch;
	struct iota_bundle *bundle;
	int ret = IOTA_OK;

	if (iota_client_get_transactions_to_approve(IOTACLIENT_RANDOMWALK_DEPTH,
			&trunk, &branch) < 0) {
		return IOTA_ERR_NETWORK;
	}
	bundle = iota_alloc_bundle(1, 0, 0, 0, 0);
	if (!bundle) {
		DPRINTF("%s: couldn't allocate memory for bundle\n", __FUNCTION__);
		return IOTA_ERR_NO_MEM;
	}
	memcpy(bundle->descr.output_txs[0].address, addr->str, NUM_ADDR_TRYTES);
	bundle->descr.output_txs[0].value = 0;
	iota_bundle_hash_ptr = &bundle->bundle_hash;
	iota_tx_ptr = &bundle->txs[0];
	iota_wallet_create_tx_bundle(iota_bundle_hash_receiver, iota_tx_receiver,
			&bundle->descr);
	if (iota_client.pow_handler) {
		DPRINTF("%s: using external PoW client\n", __FUNCTION__);
		if (iota_client.pow_handler(iota_client.pow_priv, &trunk, &branch,
				iota_client.mwm, bundle->txs, 1) < 0) {
			ret = IOTA_ERR_POW;
			goto exit;
		}
	}
	else {
		if (iota_client_attach_to_tangle(&trunk, &branch, iota_client.mwm,
				bundle->txs, 1) < 0) {
			ret = IOTA_ERR_NETWORK;
			goto exit;
		}
	}
	if (iota_client_store_transactions(bundle->txs, 1) < 0) {
		ret = IOTA_ERR_NETWORK;
		goto exit;
	}
	ret = iota_client_broadcast_transactions(bundle->txs, 1);
exit:
	iota_free_bundle(bundle);
	return ret;
}
