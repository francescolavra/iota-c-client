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

#include <simplelink.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ti/net/http/httpclient.h>

#include "../platform.h"

#define IOTA_HTTP_CONTENT_TYPE	"application/json"
#define IOTA_HTTP_API_VERSION	"1"

#ifdef IOTA_CC3220_DEBUG
#define DPRINTF	printf
#else
#define DPRINTF(fmt, ...)	do {} while(0)
#endif

struct cc3220_http {
	HTTPClient_Handle cli;
	const char *node_url;
};

void *iota_client_http_init(const char *node_url)
{
	struct cc3220_http *http = malloc(sizeof(struct cc3220_http));
	int16_t status;

	if (http == NULL) {
		DPRINTF("%s: cannot allocate memory\n", __FUNCTION__);
		return NULL;
	}
	http->cli = HTTPClient_create(&status, NULL);
	if (status < 0) {
		DPRINTF("%s: cannot create HTTP client: %d\n", __FUNCTION__, status);
		free(http);
		return NULL;
	}
	http->node_url = node_url;
	return http;
}

cJSON *iota_client_send_req(void *priv, cJSON *req, int *status_code)
{
	struct cc3220_http *http = priv;
	int ret;
	struct HTTPClient_extSecParams sec_params = {0};
	char *buf, *larger_buf;
	int req_len, resp_len = 0, read_len = 0;
	uint32_t hdr_len;
	bool more_flag;
	cJSON *resp = NULL;

	buf = cJSON_PrintUnformatted(req);
	if (!buf) {
		DPRINTF("%s: failed to write JSON request\n", __FUNCTION__);
		return NULL;
	}
	req_len = strlen(buf);
	ret = HTTPClient_setHeader(http->cli, HTTPClient_HFIELD_REQ_CONTENT_TYPE,
			IOTA_HTTP_CONTENT_TYPE, strlen(IOTA_HTTP_CONTENT_TYPE) + 1,
			HTTPClient_HFIELD_PERSISTENT);
	if (ret < 0) {
		DPRINTF("%s: cannot set Content-Type request header: %d\n",
				__FUNCTION__, ret);
		goto exit;
	}
	ret = HTTPClient_setHeaderByName(http->cli, HTTPClient_REQUEST_HEADER_MASK,
			"X-IOTA-API-Version", IOTA_HTTP_API_VERSION,
			strlen(IOTA_HTTP_API_VERSION) + 1, HTTPClient_HFIELD_PERSISTENT);
	if (ret < 0) {
		DPRINTF("%s: cannot set X-IOTA-API-Version request header: %d\n",
				__FUNCTION__, ret);
		goto exit;
	}
	if ((ret = HTTPClient_connect(http->cli, http->node_url, &sec_params, 0)) <
			0) {
		DPRINTF("%s: failed to connect: %d\n", __FUNCTION__, ret);
		goto exit;
	}
	if ((*status_code = HTTPClient_sendRequest(http->cli, HTTP_METHOD_POST, "/",
			buf, req_len, 0)) < 0) {
		DPRINTF("%s: failed to send request: %d\n", __FUNCTION__, *status_code);
		goto disconnect;
    }
	hdr_len = req_len;
	ret = HTTPClient_getHeader(http->cli, HTTPClient_HFIELD_RES_CONTENT_LENGTH,
			buf, &hdr_len, 0);
	if (ret < 0) {
		DPRINTF("%s: failed to get content length: %d\n", __FUNCTION__, ret);
		goto disconnect;
	}
	resp_len = strtoul(buf, NULL, 0);
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
	do {
		ret = HTTPClient_readResponseBody(http->cli, buf + read_len,
				resp_len - read_len, &more_flag);
		if (ret <= 0) {
			break;
		}
		read_len += ret;
	} while (more_flag);
	if (read_len <= 0) {
		DPRINTF("%s: failed to read response\n", __FUNCTION__);
	}
disconnect:
	HTTPClient_disconnect(http->cli);
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
