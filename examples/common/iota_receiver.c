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

void iota_receiver(const char *seed)
{
	iota_addr_t addr;
	int ret;
	uint64_t balance;

	if (iota_wallet_setup(seed, "https://nodes.thetangle.org") < 0) {
		printf("Cannot initialize IOTA wallet\n");
		return;
	}
	ret = iota_wallet_get_receive_addr(&addr, 1, -1, NULL);
	if (ret == IOTA_OK) {
		printf("Please send IOTAs to this address: %s\n", addr.str);
		addr.str[81] = '\0';	/* remove address checksum */
	}
	else {
		printf("Couldn't get receive address\n");
		return;
	}
	while (1) {
		ret = iota_client_get_balances(&addr, 1, &balance);
		if (ret == 0) {
			printf("Got %llu IOTAs so far\n", balance);
		}
		else {
			printf("Couldn't get balance\n");
		}
		delay(10000);
	}
}
