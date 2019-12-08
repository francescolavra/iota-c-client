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
#include <stdint.h>
#include <stdio.h>

#include <hw_types.h>
#include <NoRTOS.h>
#include <pin.h>
#include <prcm.h>
#include <rom_map.h>
#include <semaphore.h>
#include <slnetifwifi.h>
#include <ti/drivers/Power.h>
#include <ti/drivers/SPI.h>
#include <ti/drivers/UART.h>
#include <ti/net/slnetif.h>
#include <utils.h>
#include <wlan.h>

#include "../common/iota_examples.h"

#define SSID_NAME		"WIFI_SSID"
#define SECURITY_TYPE	SL_WLAN_SEC_TYPE_WPA_WPA2
#define SECURITY_KEY	"WIFI_PASSWORD"

#define WIFI_STATUS_CONNECTED	(1 << 0)
#define WIFI_STATUS_IP_ACQUIRED	(1 << 1)

#define DELAY_COUNT_PER_MSEC	13000

static UART_Handle uart_handle;

static unsigned int wifi_status;

static int uart_open(const char *path, unsigned flags, int llv_fd)
{
	return llv_fd;
}

static int uart_write(int dev_fd, const char *buf, unsigned count)
{
	UART_writePolling(uart_handle, buf, count);
	return count;
}

static void init_term(void)
{
	UART_Params uart_params;

	UART_init();
	UART_Params_init(&uart_params);
	uart_params.writeDataMode = UART_DATA_BINARY;
	uart_params.readDataMode = UART_DATA_BINARY;
	uart_params.readReturnMode = UART_RETURN_FULL;
	uart_params.readEcho = UART_ECHO_OFF;
	uart_params.baudRate = 115200;
	uart_handle = UART_open(0, &uart_params);
	add_device("uart", _SSA, uart_open, NULL, NULL, uart_write, NULL, NULL,
			NULL);
	fopen("uart", "w");
	freopen("uart:", "w", stdout);
	setvbuf(stdout, NULL, _IONBF, 0);
}

static void init_hw(void)
{
	PRCMCC3200MCUInit();
	Power_init();
	NoRTOS_start();
	SPI_init();
	init_term();
}

static int init_wifi(void)
{
	int status = sl_Start(0, 0, 0);

	if (status != ROLE_STA) {
		sl_Stop(0xFFFF);
		if ((sl_WifiConfig() < 0) || (sl_Start(0, 0, 0) != ROLE_STA)) {
			return -1;
		}
	}
	return 0;
}

static int wifi_connect(const char *ssid, const SlWlanSecParams_t *params)
{
	if (sl_WlanConnect((signed char *) ssid, strlen(ssid), 0, params, 0) < 0) {
		return -1;
	}
	while (!(wifi_status & WIFI_STATUS_CONNECTED) ||
			!(wifi_status & WIFI_STATUS_IP_ACQUIRED)) {
		printf(".");
		delay(1000);
		sl_Task(NULL);
	}
	return 0;
}

static int uart_get_cmd(char *buf, unsigned int buf_size)
{
	char c;
	int cmd_len = 0;

	while (1) {
		UART_readPolling(uart_handle, &c, 1);
		if ((c == '\r') || (c == '\n')) {
			c = '\r';
			UART_writePolling(uart_handle, &c, 1);
			c = '\n';
			UART_writePolling(uart_handle, &c, 1);
			break;
		}
		else if ((c == '\b') || (c == 0x7F)) {	/* backspace */
			if (cmd_len == 0) {
				c = '\a';
			}
			else {
				cmd_len--;
			}
			UART_writePolling(uart_handle, &c, 1);
		}
		else {
			buf[cmd_len++] = c;
			UART_writePolling(uart_handle, &c, 1);
			if (cmd_len == buf_size - 1) {
				break;
			}
		}
	}
	buf[cmd_len] = '\0';
	return cmd_len;
}

int main(void)
{
	SlWlanSecParams_t sec_params = {
			.Type = SECURITY_TYPE,
			.Key = SECURITY_KEY,
			.KeyLen = strlen(SECURITY_KEY),
	};
	static const char *seed =
			"DONOTUSETHISSEEDDONOTUSETHISSEEDDONOTUSETHISSEEDDONOTUSETHISSEEDDONOTUSETHISSEED9";

	init_hw();
	if ((init_wifi() < 0) || (wifi_connect(SSID_NAME, &sec_params) < 0)) {
		printf("Cannot connect to Wi-Fi network\n");
		return -1;
	}
	while (1) {
		char cmd[64];

		printf("Select the example to run:\n");
		printf("1. Hello IOTA\n");
		printf("2. IOTA Sender\n");
		printf("3. IOTA Receiver\n");
		if (uart_get_cmd(cmd, sizeof(cmd)) > 0) {
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

void SimpleLinkFatalErrorEventHandler(SlDeviceFatal_t *slFatalErrorEvent)
{
}

void SimpleLinkGeneralEventHandler(SlDeviceEvent_t *pDevEvent)
{
}

void SimpleLinkHttpServerEventHandler(SlNetAppHttpServerEvent_t *pHttpEvent,
		SlNetAppHttpServerResponse_t *pHttpResponse)
{
}

void SimpleLinkNetAppEventHandler(SlNetAppEvent_t *pNetAppEvent)
{
	switch (pNetAppEvent->Id) {
	case SL_NETAPP_EVENT_IPV4_ACQUIRED:
		if (wifi_status & WIFI_STATUS_CONNECTED) {
			SlNetAppEventData_u *evtData = &pNetAppEvent->Data;

			printf(" IP address acquired: %d.%d.%d.%d\n",
					(uint8_t) SL_IPV4_BYTE(evtData->IpAcquiredV4.Ip, 3),
					(uint8_t) SL_IPV4_BYTE(evtData->IpAcquiredV4.Ip, 2),
					(uint8_t) SL_IPV4_BYTE(evtData->IpAcquiredV4.Ip, 1),
					(uint8_t) SL_IPV4_BYTE(evtData->IpAcquiredV4.Ip, 0));
			wifi_status |= WIFI_STATUS_IP_ACQUIRED;
			SlNetIf_init(0);
			SlNetIf_add(SLNETIF_ID_1, "CC3220",
					(const SlNetIf_Config_t *)&SlNetIfConfigWifi, 5);
			SlNetSock_init(0);
			SlNetUtil_init(0);
		}
		break;
    case SL_NETAPP_EVENT_IPV4_LOST:
		printf(" IP address lost\n");
		wifi_status &= ~WIFI_STATUS_IP_ACQUIRED;
		break;
	}
}

void SimpleLinkNetAppRequestEventHandler(SlNetAppRequest_t *pNetAppRequest,
		SlNetAppResponse_t *pNetAppResponse)
{
}

void SimpleLinkNetAppRequestMemFreeEventHandler(uint8_t *buffer)
{
}

void SimpleLinkSocketTriggerEventHandler(SlSockTriggerEvent_t *pSlTriggerEvent)
{
}

void SimpleLinkSockEventHandler(SlSockEvent_t *pSock)
{
}

void SimpleLinkWlanEventHandler(SlWlanEvent_t *pWlanEvent)
{
	switch(pWlanEvent->Id) {
	case SL_WLAN_EVENT_CONNECT:
		printf(" STA connected to AP %s\n", pWlanEvent->Data.Connect.SsidName);
		wifi_status |= WIFI_STATUS_CONNECTED;
		break;
	case SL_WLAN_EVENT_DISCONNECT:
		printf(" STA disconnected from AP\n");
		wifi_status &= ~WIFI_STATUS_CONNECTED;
		break;
	}
}

/* Dummy implementation of semaphore initialization function for a
 * single-threaded environment (needed by the SlNetSock library). */
int sem_init(sem_t *sem, int pshared, unsigned value)
{
	return 0;
}

/* Dummy implementation of semaphore posting function for a single-threaded
 * environment (needed by the SlNetSock library). */
int sem_post(sem_t *semaphore)
{
	return 0;
}

/* Dummy implementation of semaphore waiting function for a single-threaded
 * environment (needed by the SlNetSock library). */
int sem_wait(sem_t *semaphore)
{
	return 0;
}
