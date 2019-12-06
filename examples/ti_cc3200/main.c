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

#include <file.h>
#include <hw_ints.h>
#include <hw_memmap.h>
#include <hw_types.h>
#include <interrupt.h>
#include <pin.h>
#include <prcm.h>
#include <rom_map.h>
#include <simplelink.h>
#include <example/common/common.h>
#include <example/common/network_if.h>
#include <example/common/uart_if.h>
#include <stdio.h>
#include <stdlib.h>
#include <uart.h>
#include <utils.h>

#include "../common/iota_examples.h"

#define DELAY_COUNT_PER_MSEC	13000

static void init_hw(void)
{
	extern void (* const g_pfnVectors[])(void);

	MAP_IntVTableBaseSet((unsigned long)&g_pfnVectors[0]);
	MAP_IntMasterEnable();
	MAP_IntEnable(FAULT_SYSTICK);
	PRCMCC3200MCUInit();
	MAP_PRCMPeripheralClkEnable(PRCM_UARTA0, PRCM_RUN_MODE_CLK);
	MAP_PinTypeUART(PIN_55, PIN_MODE_3);
	MAP_PinTypeUART(PIN_57, PIN_MODE_3);
	InitTerm();
}

static int uart_open(const char *path, unsigned flags, int llv_fd)
{
	return llv_fd;
}

static int uart_write(int dev_fd, const char *buf, unsigned count)
{
	int i;

	for (i = 0; i < count; i++) {
		MAP_UARTCharPut(CONSOLE, buf[i]);
	}
	return count;
}

int main(void)
{
	SlSecParams_t sec_params = {
			.Type = SECURITY_TYPE,
			.Key = SECURITY_KEY,
			.KeyLen = strlen(SECURITY_KEY),
	};
	static const char *seed =
			"DONOTUSETHISSEEDDONOTUSETHISSEEDDONOTUSETHISSEEDDONOTUSETHISSEEDDONOTUSETHISSEED9";

	init_hw();
	add_device("uart", _SSA, uart_open, NULL, NULL, uart_write, NULL, NULL,
			NULL);
	fopen("uart", "w");
	freopen("uart:", "w", stdout);
	setvbuf(stdout, NULL, _IONBF, 0);
	if ((Network_IF_InitDriver(ROLE_STA) < 0) ||
			(Network_IF_ConnectAP(SSID_NAME, sec_params) < 0)) {
		printf("Cannot connect to Wi-Fi network\n");
		return -1;
	}
	while (1) {
		char cmd[64];

		printf("Select the example to run:\n");
		printf("1. Hello IOTA\n");
		printf("2. IOTA Sender\n");
		printf("3. IOTA Receiver\n");
		if (GetCmd(cmd, sizeof(cmd)) > 0) {
			switch (atoi(cmd)) {
			case 1:
				hello_iota(seed);
				break;
			case 2:
				iota_sender(seed);
				break;
			case 3:
				iota_receiver(seed);
				break;
			}
		}
	}
}

void delay(unsigned int ms)
{
	UtilsDelay(ms * DELAY_COUNT_PER_MSEC);
}
