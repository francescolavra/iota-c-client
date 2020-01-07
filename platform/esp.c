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
#include <esp_http_client.h>
#include <string.h>

#include "../platform.h"

#ifdef IOTA_ESP_DEBUG
#define DPRINTF	printf
#else
#define DPRINTF(fmt, ...)	do {} while(0)
#endif

static esp_err_t iota_client_http_event_handler(esp_http_client_event_t *evt)
{
	switch(evt->event_id) {
	case HTTP_EVENT_ERROR:
		DPRINTF("%s: error\n", __FUNCTION__);
		break;
	case HTTP_EVENT_ON_CONNECTED:
		DPRINTF("%s: connected\n", __FUNCTION__);
		break;
	default:
		break;
    }
    return ESP_OK;
}

void *iota_client_http_init(const char *node_url)
{
	esp_http_client_config_t config;
	esp_http_client_handle_t client;
	esp_err_t err;

	memset(&config, 0, sizeof(config));
	config.url = node_url;
	config.method = HTTP_METHOD_POST;
	config.timeout_ms = 32 * 1024;
	config.event_handler = iota_client_http_event_handler;
	client = esp_http_client_init(&config);
	if (client == NULL) {
		return NULL;
	}
	if ((err = esp_http_client_set_header(client,
			"Content-Type", "application/json")) != ESP_OK) {
		DPRINTF("%s: failed to set content-type header: %s\n", __FUNCTION__,
				esp_err_to_name(err));
		goto error;
	}
	if ((err = esp_http_client_set_header(client, "X-IOTA-API-Version", "1"))
			!= ESP_OK) {
		DPRINTF("%s: failed to set API version header: %s\n", __FUNCTION__,
				esp_err_to_name(err));
		goto error;
	}
	return client;
error:
	esp_http_client_cleanup(client);
	return NULL;
}

cJSON *iota_client_send_req(void *priv, cJSON *req, int *status_code)
{
	esp_http_client_handle_t client = priv;
	esp_err_t err;
	char *buf, *larger_buf;
	int req_len, resp_len, read_len;
	cJSON *resp = NULL;

	buf = cJSON_PrintUnformatted(req);
	if (!buf) {
		DPRINTF("%s: failed to write JSON request\n", __FUNCTION__);
		return NULL;
	}
	req_len = strlen(buf);
	if ((err = esp_http_client_open(client, req_len)) != ESP_OK) {
		DPRINTF("%s: failed to connect: %s\n", __FUNCTION__,
				esp_err_to_name(err));
		goto exit;
	}
    if (esp_http_client_write(client, buf, req_len) <= 0) {
		DPRINTF("%s: failed to write data\n", __FUNCTION__);
		goto exit;
    }
	resp_len = esp_http_client_fetch_headers(client);
	*status_code = esp_http_client_get_status_code(client);
	DPRINTF("%s: status %d, content length %d\n", __FUNCTION__, *status_code,
			resp_len);
	if (resp_len >= req_len) {
		larger_buf = realloc(buf, resp_len + 1);
		if (!larger_buf) {
			DPRINTF("%s: failed to allocate memory for response\n",
					__FUNCTION__);
			goto exit;
		}
		buf = larger_buf;
	}
	read_len = esp_http_client_read(client, buf, resp_len);
	if (read_len <= 0) {
		DPRINTF("%s: failed to read response\n", __FUNCTION__);
		goto exit;
	}
	DPRINTF("%s: read length %d\n", __FUNCTION__, read_len);
	esp_http_client_close(client);
	buf[read_len] = '\0';
	resp = cJSON_Parse(buf);
	if (!resp) {
		DPRINTF("%s: failed to parse response\n", __FUNCTION__);
	}
exit:
	free(buf);
	return resp;
}
