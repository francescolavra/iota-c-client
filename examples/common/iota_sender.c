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

#include <iota_wallet.h>

#include "iota_examples.h"

void iota_sender(const char *seed)
{
	iota_addr_t recipient;
	iota_tag_t tag;
	int ret;

	if (iota_wallet_setup(seed, "https://nodes.thetangle.org") < 0) {
		printf("Cannot initialize IOTA wallet\n");
		return;
	}
	sprintf(recipient.str,
			"DONOTUSETHISADDRESSDONOTUSETHISADDRESSDONOTUSETHISADDRESSDONOTUSETHISADDRESS99999UZ9WVXEDW");
	sprintf(tag.str, "TAGTAGTAGTAGTAGTAGTAGTAGTAG");
	if (iota_addr_verify_cksum(&recipient) == IOTA_OK) {
		printf("Sending IOTAs...\n");
		ret = iota_wallet_send_transfer(1, &recipient, &tag, -1, NULL,
				-1, NULL);
		printf("Transfer result: %d (%s)\n", ret,
				(ret == IOTA_OK) ? "OK": "error");
	}
	else {
		printf("Invalid recipient address\n");
	}
}
