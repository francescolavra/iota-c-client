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

#ifndef _IOTA_WALLET_H_
#define _IOTA_WALLET_H_

#include <stdint.h>

#include "iota_common.h"
#include "pow_client.h"

struct iota_addr_with_balance {
	int addr_idx;
	uint64_t balance;
};

/** Initialize IOTA wallet to manage funds associated to a IOTA seed
  @param seed  NULL-terminated string containing 81-character IOTA seed
  @param node_url  URL used to communicate with full IOTA node
  @return 0 if successful, negative number otherwise
*/
int iota_wallet_setup(const char *seed, const char *node_url);

/** Retrieve current security level
  The security level is an integer number between 1 and 3 that is used to
  generate IOTA addresses and to sign transactions.
  @return current security level
*/
unsigned int iota_wallet_get_security_level(void);

/** Configure security level
  The security level is an integer number between 1 and 3 that is used to
  generate IOTA addresses and to sign transactions.
  @param security  Security level
  @return 0 if supplied security level is valid, negative number otherwise
*/
int iota_wallet_set_security_level(unsigned int security);

/** Retrieve current minimum weight magnitude
  The minimum weight magnitude is an integer number used to perform Proof of
  Work when attaching transactions to the tangle.
  @return current minimum weight magnitude
*/
unsigned int iota_wallet_get_mwm(void);

/** Configure minimum weight magnitude
  The minimum weight magnitude is an integer number used to perform Proof of
  Work when attaching transactions to the tangle.
  @param mwm  Minimum weight magnitude
  @return none
*/
void iota_wallet_set_mwm(unsigned int mwm);

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
void iota_wallet_set_pow_handler(pow_handler_t handler, void *priv);

/** Retrieve IOTA balance in the wallet
  This function works by requesting from the connected IOTA full node the
  balances associated to a series of consecutive addresses derived from the
  seed, and summing those balances.
  @param balance  Pointer to variable that will hold the retrieved balance,
         expressed in IOTAs
  @param start_addr_idx  Starting index to be used to generate the first
         address for which the balance is requested from the full node
  @param next_addr_idx  Pointer to variable where the index of the first
         address for which the balance has not been requested will be
         stored; if NULL, this information is not returned; this parameter can
         be used when doing multiple calls to this function where the next call
         uses a "start_addr_idx" argument set to the value stored in the
         "next_addr_idx" argument in the previous call
  @return 0 if communication with the IOTA full node is successful, negative
          number otherwise
*/
int iota_wallet_get_balance(uint64_t *balance, unsigned int start_addr_idx,
		unsigned int *next_addr_idx);

/** Retrieve an address that can be used to receive an IOTA transfer
  This function works by querying the connected IOTA full node whether
  addresses derived from the seed have been spent from, and returning the
  first address that has not been spent from.
  @param addr  Pointer to variable that will hold an address that can be
         used to receive an IOTA transfer
  @param with_checksum  boolean value indicating whether the returned address
         should have the 9-tryte checksum appended to it
  @param start_idx  Starting index to be used to generate the first address
         for which the spending status is requested from the full node; if
         -1, this function manages internally the address indexes, possibly
         returning results cached from previous function calls
  @param addr_idx  Pointer to variable where the index of the first
         unspent address will be stored; if NULL, this information is not
         returned
  @return 0 if communication with the IOTA full node is successful, negative
          number otherwise
*/
int iota_wallet_get_receive_addr(iota_addr_t *addr, int with_checksum,
		unsigned int start_idx, unsigned int *addr_idx);

/** Send a IOTA amount to a recipient address
  This function works by requesting from the connected IOTA full node the
  balances associated to a series of consecutive addresses derived from the
  seed, until the transfer amount is covered. In addition, if the amount is
  less than the retrieved balance, the remainder is sent to an unspent
  address (the "change" address), also derived from the seed.
  @param value  IOTA amount to be sent to recipient
  @param recipient  Address of recipient; it must have the 9-tryte checksum
         appended to it
  @param tag  Transaction tag (up to 27 trytes); can be NULL, in which case a
         default tag is used
  @param input_start_idx  Starting index to be used to generate the first
         address for which the balance is requested from the full node
  @param input_addr_idx  Pointer to variable where the index of the first
         address for which the balance has not been used will be
         stored; if NULL, this information is not returned; this parameter can
         be used when doing multiple calls to this function where the next call
         uses a "input_start_idx" argument set to the value stored in the
         "input_addr_idx" argument in the previous call; in this way,
         unnecessary queries to the IOTA full node to retrieve the available
         balance can be avoided
  @param change_start_idx  Starting index to be used to search for the address
         to which the remainder from the IOTA transfer is sent ("change"
         address); if -1, this function manages internally the change address,
         possibly using information cached from previous function calls
  @param change_addr_idx  Pointer to variable where the index of the change
         address will be stored; if NULL, this information is not returned
  @return result codes:
          IOTA_OK: transfer executed successfully
          IOTA_ERR_INV_ADDR: invalid recipient address
          IOTA_ERR_INV_TAG: invalid transaction tag
          IOTA_ERR_NETWORK: communication with IOTA full node failed
          IOTA_ERR_FRAGM_BALANCE: the IOTA amount needed for the transfer is
                                  split between too many addresses
          IOTA_ERR_INSUFF_BALANCE: the IOTA amount needed for the transfer
                                   is not available in addresses derived
                                   from the seed
          IOTA_ERR_POW: Proof of Work executed from user-supplied PowClient
                        failed
          IOTA_ERR_POW: memory allocation error
*/
int iota_wallet_send_transfer(uint64_t value, const iota_addr_t *recipient,
		const iota_tag_t *tag, unsigned int input_start_idx,
		unsigned int *input_addr_idx, unsigned int change_start_idx,
		unsigned int *change_addr_idx);

/** Generate IOTA public address from private seed
  @param addr  pointer where generated address is stored; the address is
         expressed as a 81-character string (with a 9-character checksum
         appended if the "with_checksum" argument value is non-zero)
  @param index  Index to be used to generate the address
  @param with_checksum  boolean value indicating whether the returned address
         should have the 9-tryte checksum appended to it
  @return none
*/
void iota_wallet_get_addr(iota_addr_t *addr, unsigned int index,
		int with_checksum);

/** Retrieve address indexes with positive balance
  This function works by requesting from the connected IOTA full node the
  balances associated to a series of consecutive addresses derived from the
  seed, until the needed balance (if not zero) is covered.
  @param list  Pointer to array to be filled with iota_addr_with_balance
         structures with information on address indexes and corresponding
         balance; if NULL, this information is not returned
  @param list_size  Size of the list array, i.e. maximum number of elements to
         be put in the list
  @param total_balance  Pointer to variable that will hold the total
         retrieved balance, i.e. the sum of balances from addresses found
         with positive balance; if NULL, this information is not returned
  @param needed_balance  If not zero, the search for addresses with positive
         balance is stopped as soon as the total retrieved balance is at
         least this amount
  @param start_addr_idx  Starting index to be used to generate the first
         address for which the balance is requested from the full node
  @param next_addr_idx  Pointer to variable where the index of the first
         address for which the balance has not been retrieved will be
         stored; if NULL, this information is not returned; this parameter can
         be used when doing multiple calls to this function where the next call
         uses a "start_addr_idx" argument set to the value stored in the
         "next_addr_idx" argument in the previous call; in this way, unnecessary
         queries to the IOTA full node to retrieve the available balance can be
         avoided
  @return number of elements put in the iota_addr_with_balance structure array
          if communication with the IOTA full node is successful, negative
          number otherwise
*/
int iota_wallet_get_addrs_with_balance(struct iota_addr_with_balance *list,
		int list_size, uint64_t *total_balance, uint64_t needed_balance,
		unsigned int start_addr_idx, unsigned int *next_addr_idx);

/** Retrieve addresses with transactions in the tangle
  This function works by querying the connected IOTA full node to search for
  transactions containing addresses derived from the private seed, starting
  from address index 0. Note that if a given address is not returned in the
  list of addresses, that doens't mean that the address has never been used,
  because any transactions using that address might have been purged from
  the IOTA node when making a snapshot.
  @param addrs  Array to be filled with addresses for which at least a
         transaction has been found in the tangle
  @param size  Size of the addrs array, i.e. maximum number of elements to
         be put in the array
  @return number of addresses put in the array if communication with the IOTA
          full node is successful, negative number otherwise
*/
int iota_wallet_find_addrs(iota_addr_t *addrs, int size);

#endif
