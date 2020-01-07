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

#include <esp_err.h>
#include <esp_event_loop.h>
#include <esp_wifi.h>
#include <nvs_flash.h>
#include <stdio.h>
#include <string.h>

#include "iota_examples.h"

static volatile int wifi_ok = 0;

static esp_err_t wifi_event_handler(void *ctx, system_event_t *event)
{
	esp_err_t ret = ESP_OK;

	switch (event->event_id) {
	case SYSTEM_EVENT_STA_START:
		ret = esp_wifi_connect();
		if (ret != ESP_OK) {
			printf("%s: cannot connect to access point, error %d\n",
					__FUNCTION__, ret);
		}
		break;
	case SYSTEM_EVENT_STA_CONNECTED:
		printf("%s: sta connected\n", __FUNCTION__);
		break;
	case SYSTEM_EVENT_STA_GOT_IP:
		printf("%s: sta got IP address\n", __FUNCTION__);
		wifi_ok = 1;
		break;
	case SYSTEM_EVENT_STA_LOST_IP:
		printf("%s: sta lost IP address\n", __FUNCTION__);
		wifi_ok = 0;
		break;
	case SYSTEM_EVENT_STA_DISCONNECTED:
		printf("%s: sta disconnected\n", __FUNCTION__);
		wifi_ok = 0;
		break;
	default:
		break;
	}
    return ret;
}

static void wifi_init(const char *ssid, const char *pwd)
{
	tcpip_adapter_init();
	ESP_ERROR_CHECK(esp_event_loop_init(wifi_event_handler, NULL));

	wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
	ESP_ERROR_CHECK(esp_wifi_init(&cfg));
	ESP_ERROR_CHECK(esp_wifi_set_storage(WIFI_STORAGE_RAM));
	ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));

	wifi_config_t wifi_config;
	memset(&wifi_config, 0, sizeof(wifi_config));
	strcpy((char *)wifi_config.sta.ssid, ssid);
	strcpy((char *)wifi_config.sta.password, pwd);
	ESP_ERROR_CHECK(esp_wifi_set_config(ESP_IF_WIFI_STA, &wifi_config));

	ESP_ERROR_CHECK(esp_wifi_start());
}

void app_main()
{
	static const char *seed = CONFIG_IOTA_SEED;

	ESP_ERROR_CHECK(nvs_flash_init());
	wifi_init(CONFIG_IOTA_WIFI_SSID, CONFIG_IOTA_WIFI_PWD);
	while (!wifi_ok) {
		vTaskDelay(1000 / portTICK_PERIOD_MS);
	}
#if CONFIG_IOTA_EXAMPLE_HELLO
	hello_iota(seed);
#elif CONFIG_IOTA_EXAMPLE_SENDER
	iota_sender(seed);
#elif CONFIG_IOTA_EXAMPLE_RECEIVER
	iota_receiver(seed);
#endif
}

void delay(unsigned int ms)
{
	vTaskDelay(ms / portTICK_PERIOD_MS);
}
