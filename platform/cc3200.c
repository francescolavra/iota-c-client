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

#include <http/client/httpcli.h>
#include <stdio.h>
#include <stdlib.h>

#include "../platform.h"

#ifdef IOTA_CC3200_DEBUG
#define DPRINTF	printf
#else
#define DPRINTF(fmt, ...)	do {} while(0)
#endif

struct cc3200_http {
	HTTPCli_Struct cli;
	char host[128];
	struct sockaddr addr;
	int flags;
	HTTPCli_Field req_fields[4];
	const char *resp_fields[2];
};

void *iota_client_http_init(const char *node_url)
{
	struct cc3200_http *http = malloc(sizeof(struct cc3200_http));
	int ret;
	char *str;

	if (http == NULL) {
		return NULL;
	}
	ret = HTTPCli_initSockAddr(&http->addr, node_url, 0);
	if (ret) {
		DPRINTF("%s: failed to get address from node URL: %d\n", __FUNCTION__,
				ret);
		goto error;
	}
	if (!strncmp(node_url, "https", 5)) {
		SlDateTime_t g_time;
		struct HTTPCli_SecureParams params = {0};

		g_time.sl_tm_day = 5;
		g_time.sl_tm_mon = 12;
		g_time.sl_tm_year = 2019;
		g_time.sl_tm_sec = 0;
		g_time.sl_tm_hour = 0;
		g_time.sl_tm_min = 0;
		sl_DevSet(SL_DEVICE_GENERAL_CONFIGURATION,
				SL_DEVICE_GENERAL_CONFIGURATION_DATE_TIME, sizeof(SlDateTime_t),
				(unsigned char *) &g_time);
		strcpy(params.cafile, "/cert/ca.pem");
		HTTPCli_setSecureParams(&params);
		http->flags = HTTPCli_TYPE_TLS;
	}
	else {
		http->flags = 0;
	}
	str = strstr(node_url, "//");
	if (str) {
		str += 2;
	}
	else {
		str = (char *) node_url;
	}
	strncpy(http->host, str, sizeof(http->host) - 1);
	http->host[sizeof(http->host) - 1] = '\0';

	/* Strip port number, if any, from URI. */
	str = strchr(http->host, ':');
	if (str) {
		*str = '\0';
	}

	http->req_fields[0].name = HTTPCli_FIELD_NAME_HOST;
	http->req_fields[0].value = http->host;
	http->req_fields[1].name = HTTPCli_FIELD_NAME_CONTENT_TYPE;
	http->req_fields[1].value = "application/json";
	http->req_fields[2].name = "X-IOTA-API-Version";
	http->req_fields[2].value = "1";
	http->req_fields[3].name = http->req_fields[3].value = NULL;
	http->resp_fields[0]= HTTPCli_FIELD_NAME_CONTENT_LENGTH;
	http->resp_fields[1]= NULL;
	return http;
error:
	free(http);
	return NULL;
}

cJSON *iota_client_send_req(void *priv, cJSON *req, int *status_code)
{
	struct cc3200_http *http = priv;
	int ret;
	char *buf, *larger_buf;
	char content_len[8];
	int req_len, resp_len = 0, read_len = 0;
	bool more_flag;
	cJSON *resp = NULL;

	buf = cJSON_PrintUnformatted(req);
	if (!buf) {
		DPRINTF("%s: failed to write JSON request\n", __FUNCTION__);
		return NULL;
	}
	req_len = strlen(buf);
	HTTPCli_construct(&http->cli);
	HTTPCli_setRequestFields(&http->cli, http->req_fields);
	HTTPCli_setResponseFields(&http->cli, http->resp_fields);
	if ((ret = HTTPCli_connect(&http->cli, &http->addr, http->flags, NULL)) < 0)
	{
		DPRINTF("%s: failed to connect: %d\n", __FUNCTION__, ret);
		goto exit;
	}
	sprintf(content_len, "%d", req_len);
	if ((HTTPCli_sendRequest(&http->cli, HTTPCli_METHOD_POST, "/", true) < 0) ||
			(HTTPCli_sendField(&http->cli, HTTPCli_FIELD_NAME_CONTENT_LENGTH,
			content_len, true) < 0) ||
			(HTTPCli_sendRequestBody(&http->cli, buf, req_len) < 0)) {
		DPRINTF("%s: failed to write data\n", __FUNCTION__);
		goto disconnect;
    }
	*status_code = HTTPCli_getResponseStatus(&http->cli);
	do {
		ret = HTTPCli_getResponseField(&http->cli, buf, req_len, &more_flag);
		switch (ret) {
		case 0:
			resp_len = strtoul(buf, NULL, 0);
			break;
		default:
			break;
		}
	} while (ret != HTTPCli_FIELD_ID_END);
	DPRINTF("%s: status %d, content length %d\n", __FUNCTION__, *status_code,
			resp_len);
	if (resp_len >= req_len) {
		larger_buf = realloc(buf, resp_len + 1);
		if (!larger_buf) {
			DPRINTF("%s: failed to allocate memory for response\n",
					__FUNCTION__);
			goto disconnect;
		}
		buf = larger_buf;
	}
	read_len = HTTPCli_readResponseBody(&http->cli, buf, resp_len, &more_flag);
	if (read_len <= 0) {
		DPRINTF("%s: failed to read response\n", __FUNCTION__);
	}
disconnect:
	HTTPCli_disconnect(&http->cli);
	if (read_len > 0) {
		DPRINTF("%s: read length %d\n", __FUNCTION__, read_len);
		buf[read_len] = '\0';
		resp = cJSON_Parse(buf);
		if (!resp) {
			DPRINTF("%s: failed to parse response\n", __FUNCTION__);
		}
	}
exit:
	free(buf);
	return resp;
}
