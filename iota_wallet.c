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

#include "iota_client.h"
#include "iota_utils.h"
#include "iota_wallet.h"

#include "iota-c-library/src/iota/addresses.h"
#include "iota-c-library/src/iota/bundle.h"
#include "iota-c-library/src/iota/common.h"
#include "iota-c-library/src/iota/conversion.h"

#define IOTAWALLET_ADDR_QUERY_SIZE	8
#define IOTAWALLET_RANDOMWALK_DEPTH	3

#ifdef IOTAWALLET_DEBUG
#define DPRINTF	printf
#else
#define DPRINTF(fmt, ...)	do {} while(0)
#endif

static struct {
	unsigned char seed_bytes[NUM_HASH_BYTES];
	unsigned int security;
	unsigned int mwm;
	int first_unspent_addr, last_spent_addr;
	pow_handler_t pow_handler;
	void *pow_priv;
} iota_wallet;

static int iota_wallet_find_addr(iota_addr_t *addr) {
	iota_hash_t tx;

	return iota_client_find_transactions(&tx, 1, NULL, 0, addr, 1, NULL, 0,
			NULL, 0);
}

static int iota_wallet_transfer_check(uint64_t value,
		const iota_addr_t *recipient, unsigned int change_start_idx,
		unsigned int *change_addr_idx, iota_tx_raw_t *txs,
		unsigned int tx_count)
{
#ifdef IOTAWALLET_PARANOID
	unsigned int i;
	iota_addr_t addrs[(tx_count - 1) / iota_wallet.security];
	uint64_t balances[(tx_count - 1) / iota_wallet.security];
	int64_t tx_value;
	int input_count;

	if (iota_tx_get_value(&txs[tx_count - 1]) != value) {
		DPRINTF("%s: invalid transaction output value\n", __FUNCTION__);
		return -1;
	}
	input_count = 0;
	for (i = 0; i < tx_count - 1; i++) {
		if (iota_tx_get_value(&txs[i]) < 0) {
			iota_tx_get_addr(&txs[i], &addrs[input_count++]);
		}
	}
	if (iota_client_get_balances(addrs, input_count, balances) < 0) {
		DPRINTF("%s: could not retrieve balances\n", __FUNCTION__);
		return -1;
	}
	input_count = 0;
	for (i = 0; i < tx_count - 1; i++) {
		tx_value = iota_tx_get_value(&txs[i]);
		if (tx_value < 0) {
			if (-tx_value != balances[input_count]) {
				DPRINTF("%s: transaction value %lld for input %d different from"
						" address balance %llu\n", __FUNCTION__, -tx_value,
						input_count, balances[input_count]);
				return -1;
			}
			input_count++;
		}
	}
	if (iota_tx_get_value(&txs[0]) > 0) {
		iota_addr_t change_addr;
		int spent;
		unsigned int change_end_idx;

		iota_tx_get_addr(&txs[0], &change_addr);
		for (i = 0; i < input_count; i++) {
			if (!memcmp(&change_addr.str, &addrs[i].str, NUM_ADDR_TRYTES)) {
				DPRINTF("%s: change address equal to input address %d\n",
						__FUNCTION__, i);
				return -1;
			}
		}
		if (iota_client_were_addresses_spent_from(&change_addr, 1, &spent) < 0)
		{
			DPRINTF("%s: could not spent status\n", __FUNCTION__);
			return -1;
		}
		if (spent) {
			DPRINTF("%s: change address already spent from\n", __FUNCTION__);
			return -1;
		}
		if (change_addr_idx != NULL) {
			change_start_idx = *change_addr_idx;
			change_end_idx = change_start_idx + 1;
		}
		else {
			if (change_start_idx == (unsigned int)-1) {
				change_start_idx = 0;
			}
			change_end_idx = (unsigned int)-1;
		}
		for (i = change_start_idx; i < change_end_idx; i++) {
			DPRINTF("%s: checking address index %d\n", __FUNCTION__, i);
			iota_wallet_get_addr(&addrs[0], i, 0);
			if (!memcmp(&addrs[0].str, &change_addr.str, NUM_ADDR_TRYTES)) {
				break;
			}
		}
		if (i == change_end_idx) {
			DPRINTF("%s: change address does not belong to wallet\n",
					__FUNCTION__);
			return -1;
		}
	}
#endif
	return 0;
}

int iota_wallet_setup(const char *seed, const char *node_url)
{
	int ret;

	if (strlen(seed) != NUM_HASH_TRYTES) {
		return IOTA_ERR_INV_SEED;
	}
	iota_wallet_init();
	chars_to_bytes(seed, iota_wallet.seed_bytes, NUM_HASH_TRYTES);
	ret = iota_client_init(node_url);
	if (ret < 0) {
		return ret;
	}
	iota_wallet.security = 2;
	iota_wallet.mwm = 14;
	iota_wallet.pow_handler = NULL;
	iota_wallet.first_unspent_addr = iota_wallet.last_spent_addr = -1;
	return IOTA_OK;
}

unsigned int iota_wallet_get_security_level(void)
{
	return iota_wallet.security;
}

int iota_wallet_set_security_level(unsigned int security)
{
	if (!in_range(security, MIN_SECURITY_LEVEL, MAX_SECURITY_LEVEL)) {
		return -1;
	}
	iota_wallet.security = security;
	return 0;
}

unsigned int iota_wallet_get_mwm(void)
{
	return iota_wallet.mwm;
}

void iota_wallet_set_mwm(unsigned int mwm)
{
	iota_wallet.mwm = mwm;
}

void iota_wallet_set_pow_handler(pow_handler_t handler, void *priv)
{
	iota_wallet.pow_handler = handler;
	iota_wallet.pow_priv = priv;
}

int iota_wallet_get_balance(uint64_t *balance, unsigned int start_addr_idx,
		unsigned int *next_addr_idx)
{
	return iota_wallet_get_addrs_with_balance(NULL, 0, balance, 0,
			start_addr_idx, next_addr_idx);
}

int iota_wallet_get_receive_addr(iota_addr_t *addr, int with_checksum,
		unsigned int start_idx, unsigned int *addr_idx)
{
	iota_addr_t addrs[IOTAWALLET_ADDR_QUERY_SIZE];
	int spent[IOTAWALLET_ADDR_QUERY_SIZE];
	int idx;

	if ((start_idx == (unsigned int)-1) &&
			(iota_wallet.first_unspent_addr >= 0)) {
		iota_wallet_get_addr(addr, iota_wallet.first_unspent_addr,
				with_checksum);
		if (addr_idx) {
			*addr_idx = iota_wallet.first_unspent_addr;
		}
		return IOTA_OK;
	}
	idx = ((start_idx != (unsigned int)-1) ? start_idx :
			(iota_wallet.last_spent_addr + 1));
	while (1) {
		for (int i = 0; i < IOTAWALLET_ADDR_QUERY_SIZE; i++) {
			iota_wallet_get_addr(&addrs[i], idx, 0);
			idx++;
		}
		if (iota_client_were_addresses_spent_from(addrs,
				IOTAWALLET_ADDR_QUERY_SIZE, spent) < 0) {
			DPRINTF("%s: couldn't get spent addresses\n", __FUNCTION__);
			return IOTA_ERR_NETWORK;
		}
		for (int i = 0; i < IOTAWALLET_ADDR_QUERY_SIZE; i++) {
			if (!spent[i]) {
				if (with_checksum) {
					unsigned char addrBytes[NUM_HASH_BYTES];

					chars_to_bytes(addrs[i].str, addrBytes, NUM_HASH_TRYTES);
					get_address_with_checksum(addrBytes, addr->str);
					addr->str[NUM_HASH_TRYTES + NUM_ADDR_CKSUM_TRYTES] = '\0';
				}
				else {
					memcpy(addr, &addrs[i], sizeof(*addr));
				}
				if (addr_idx) {
					*addr_idx = idx - IOTAWALLET_ADDR_QUERY_SIZE + i;
				}
				if (start_idx == (unsigned int)-1) {
					iota_wallet.first_unspent_addr =
							idx - IOTAWALLET_ADDR_QUERY_SIZE + i;
				}
				return IOTA_OK;
			}
			else if (start_idx == (unsigned int)-1) {
				iota_wallet.last_spent_addr =
						idx - IOTAWALLET_ADDR_QUERY_SIZE + i;
			}
		}
	}
}

int iota_wallet_send_transfer(uint64_t value, const iota_addr_t *recipient,
		const iota_tag_t *tag, unsigned int input_start_idx,
		unsigned int *input_addr_idx, unsigned int change_start_idx,
		unsigned int *change_addr_idx)
{
	int tag_len = 0;
	struct iota_addr_with_balance input_addrs[(MAX_BUNDLE_INDEX_SZ - 2) /
			iota_wallet.security];
	uint64_t available_balance;
	int input_count = 0;
	struct iota_bundle *bundle;
	iota_hash_t trunk, branch;
	unsigned int tx_count;
	int ret = IOTA_OK;

	if (iota_addr_verify_cksum(recipient) < 0) {
		return IOTA_ERR_INV_ADDR;
	}
	if (tag) {
		tag_len = strlen(tag->str);
		if (tryte_chars_validate(tag->str, tag_len) < 0) {
			return IOTA_ERR_INV_TAG;
		}
	}
	if (value != 0) {
		input_count = iota_wallet_get_addrs_with_balance(input_addrs,
				(MAX_BUNDLE_INDEX_SZ - 2) / iota_wallet.security,
				&available_balance, value, input_start_idx, input_addr_idx);
		if (input_count < 0) {
			DPRINTF("%s: couldn't get addresses with balance\n", __FUNCTION__);
			return IOTA_ERR_NETWORK;
		}
		DPRINTF("%s: found %d input address(es), with total balance %llu\n",
				__FUNCTION__, input_count, available_balance);
		if (available_balance < value) {
			if (input_count == (MAX_BUNDLE_INDEX_SZ - 2) / iota_wallet.security)
			{
				return IOTA_ERR_FRAGM_BALANCE;
			}
			else {
				return IOTA_ERR_INSUFF_BALANCE;
			}
		}
	}
	bundle = iota_alloc_bundle(1, 0, input_count, iota_wallet.security,
			(value != 0) && (available_balance > value));
	if (!bundle) {
		DPRINTF("%s: couldn't allocate memory for bundle\n", __FUNCTION__);
		return IOTA_ERR_NO_MEM;
	}
	memcpy(bundle->descr.output_txs[0].address, recipient->str,
			sizeof(bundle->descr.output_txs[0].address));
	bundle->descr.output_txs[0].value = (int64_t)value;
	if (tag) {
		memcpy(bundle->descr.output_txs[0].tag, tag->str, tag_len);
	}
	if (value != 0) {
		bytes_to_chars(iota_wallet.seed_bytes, bundle->descr.seed,
				sizeof(iota_wallet.seed_bytes));
		for (int i = 0; i < input_count; i++) {
			iota_addr_t addr;

			iota_wallet_get_addr(&addr, input_addrs[i].addr_idx, 0);
			memcpy(bundle->descr.input_txs[i].address, addr.str,
					sizeof(bundle->descr.input_txs[i].address));
			bundle->descr.input_txs[i].key_index = input_addrs[i].addr_idx;
			bundle->descr.input_txs[i].value = input_addrs[i].balance;
			DPRINTF("%s: input %d: key index %d, address %s, value %llu\n",
					__FUNCTION__, i, bundle->descr.input_txs[i].key_index,
					addr.str, bundle->descr.input_txs[i].value);
		}
		available_balance -= value;

		if (available_balance != 0) {
			iota_addr_t change_addr;
			unsigned int idx;

			while (1) {
				if (iota_wallet_get_receive_addr(&change_addr, 0,
						change_start_idx, &idx) < 0) {
					DPRINTF("%s: couldn't get change address\n", __FUNCTION__);
					ret = IOTA_ERR_NETWORK;
					goto exit;
				}
				for (int i = 0; i < input_count; i++) {
					if (input_addrs[i].addr_idx == idx) {
						change_start_idx = idx + 1;
						break;
					}
				}
				if (change_start_idx == idx + 1) {
					DPRINTF("%s: address index %u found in input list, "
							"searching for another change address\n",
							__FUNCTION__, idx);
					continue;
				}
				else {
					break;
				}
			}
			if (change_addr_idx != NULL) {
				*change_addr_idx = idx;
			}
			memcpy(bundle->descr.change_tx->address, change_addr.str,
					sizeof(bundle->descr.change_tx->address));
			bundle->descr.change_tx->value = (int64_t)available_balance;
			if (tag) {
				memcpy(bundle->descr.change_tx->tag, tag->str, tag_len);
			}
			DPRINTF("%s: change transaction: address %s, value %llu\n",
					__FUNCTION__, change_addr.str,
					bundle->descr.change_tx->value);
		}
	}
	if (iota_client_get_transactions_to_approve(IOTAWALLET_RANDOMWALK_DEPTH,
			&trunk, &branch) < 0) {
		DPRINTF("%s: couldn't get transactions to approve\n", __FUNCTION__);
		ret = IOTA_ERR_NETWORK;
		goto exit;
	}
	tx_count = bundle->descr.output_txs_length +
			bundle->descr.input_txs_length * iota_wallet.security +
			!!bundle->descr.change_tx;
	iota_bundle_hash_ptr = &bundle->bundle_hash;
	iota_tx_ptr = &bundle->txs[tx_count - 1];
	DPRINTF("%s: creating bundle with %d output transaction(s), %d input "
			"transaction(s) and %s change transaction\n", __FUNCTION__,
			bundle->descr.output_txs_length, bundle->descr.input_txs_length,
			bundle->descr.change_tx ? "1" : "no");
	iota_wallet_create_tx_bundle(iota_bundle_hash_receiver, iota_tx_receiver,
			&bundle->descr);
	if (iota_wallet_transfer_check(value, recipient, change_start_idx,
			change_addr_idx, bundle->txs, tx_count) < 0) {
		ret = IOTA_ERR_INTERNAL;
		goto exit;
	}
	if (iota_wallet.pow_handler) {
		DPRINTF("%s: using external PoW client\n", __FUNCTION__);
		if (iota_wallet.pow_handler(iota_wallet.pow_priv, &trunk, &branch,
				iota_wallet.mwm, bundle->txs, tx_count, bundle->txs_with_pow) <
				0) {
			ret = IOTA_ERR_POW;
			goto exit;
		}
	}
	else {
		if (iota_client_attach_to_tangle(&trunk, &branch, iota_wallet.mwm,
				bundle->txs, tx_count, bundle->txs_with_pow) < 0) {
			DPRINTF("%s: couldn't attach to tangle\n", __FUNCTION__);
			ret = IOTA_ERR_NETWORK;
			goto exit;
		}
	}
	if (iota_client_store_transactions(bundle->txs_with_pow, tx_count) < 0) {
		DPRINTF("%s: couldn't store transactions\n", __FUNCTION__);
		ret = IOTA_ERR_NETWORK;
		goto exit;
	}
	if (value != 0) {
		iota_wallet.first_unspent_addr = -1;
		if (input_addr_idx == NULL) {
			iota_wallet.last_spent_addr = input_addrs[input_count - 1].addr_idx;
		}
	}
	ret = (iota_client_broadcast_transactions(bundle->txs_with_pow, tx_count) ==
			0) ? IOTA_OK : IOTA_ERR_NETWORK;
exit:
	iota_free_bundle(bundle);
	return ret;
}

void iota_wallet_get_addr(iota_addr_t *addr, unsigned int index,
		int with_checksum)
{
	unsigned char addrBytes[NUM_HASH_BYTES];

	get_public_addr(iota_wallet.seed_bytes, index, iota_wallet.security,
			addrBytes);
	if (with_checksum) {
		get_address_with_checksum(addrBytes, addr->str);
		addr->str[NUM_HASH_TRYTES + NUM_ADDR_CKSUM_TRYTES] = '\0';
	}
	else {
		bytes_to_chars(addrBytes, addr->str, NUM_HASH_BYTES);
		addr->str[NUM_HASH_TRYTES] = '\0';
	}
}

int iota_wallet_get_addrs_with_balance(struct iota_addr_with_balance *list,
		int list_size, uint64_t *total_balance, uint64_t needed_balance,
		unsigned int start_addr_idx, unsigned int *next_addr_idx)
{
	iota_addr_t addrs[IOTAWALLET_ADDR_QUERY_SIZE];
	uint64_t balances[IOTAWALLET_ADDR_QUERY_SIZE];
	int spent[IOTAWALLET_ADDR_QUERY_SIZE];
	unsigned int addr_idx = start_addr_idx;
	uint64_t partial_balance;
	int list_count = 0;
	uint64_t balance = 0;
	int spent_any;

	while (1) {
		for (int i = 0; i < IOTAWALLET_ADDR_QUERY_SIZE; i++) {
			iota_wallet_get_addr(&addrs[i], addr_idx, 0);
			addr_idx++;
		}
		if (iota_client_get_balances(addrs, IOTAWALLET_ADDR_QUERY_SIZE,
				balances) < 0) {
			DPRINTF("%s: couldn't get balances\n", __FUNCTION__);
			return IOTA_ERR_NETWORK;
		}
		partial_balance = 0;
		for (int i = 0; i < IOTAWALLET_ADDR_QUERY_SIZE; i++) {
			if (balances[i] != 0) {
				partial_balance += balances[i];
				if (list && (list_count < list_size)) {
					list[list_count].addr_idx =
							addr_idx - IOTAWALLET_ADDR_QUERY_SIZE + i;
					list[list_count].balance = balances[i];
					list_count++;
				}
				if ((needed_balance != 0) &&
						(balance + partial_balance >= needed_balance)) {
					balance += partial_balance;
					addr_idx -= IOTAWALLET_ADDR_QUERY_SIZE - 1 - i;
					goto done;
				}
			}
		}
		if (partial_balance > 0) {
			balance += partial_balance;
			continue;
		}
		if (iota_client_were_addresses_spent_from(addrs,
				IOTAWALLET_ADDR_QUERY_SIZE, spent) < 0) {
			DPRINTF("%s: couldn't get spent addresses\n", __FUNCTION__);
			return IOTA_ERR_NETWORK;
		}
		spent_any = 0;
		for (int i = 0; i < IOTAWALLET_ADDR_QUERY_SIZE; i++) {
			spent_any |= spent[i];
		}
		if (spent_any) {
			continue;
		}
		else {
			break;
		}
	}
done:
	if (total_balance) {
		*total_balance = balance;
	}
	if (next_addr_idx) {
		*next_addr_idx = addr_idx;
	}
	return list_count;
}

int iota_wallet_find_addrs(iota_addr_t *addrs, int size)
{
	unsigned int addr_index;
	unsigned char addrBytes[NUM_HASH_BYTES];
	int addr_found;
	int addr_count = 0;

	for (addr_index = 0; addr_index < size; addr_index++) {
		get_public_addr(iota_wallet.seed_bytes, addr_index,
				iota_wallet.security, addrBytes);
		bytes_to_chars(addrBytes, addrs[addr_count].str, NUM_HASH_BYTES);
		addrs[addr_count].str[NUM_ADDR_TRYTES] = '\0';
		addr_found = iota_wallet_find_addr(&addrs[addr_count]);
		if (addr_found < 0) {
			return addr_found;
		}
		if (!addr_found) {
			break;
		}
		addr_count++;
	}
	DPRINTF("%s: found %d address(es)\n", __FUNCTION__, addr_count);
	return addr_count;
}
