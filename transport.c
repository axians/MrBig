#include "mrbig.h"
#include <winhttp.h>

static int to_wstr(const char *src, wchar_t *dst, size_t dst_count)
{
	int n;

	if (!src || !dst || dst_count == 0) return 0;
	n = MultiByteToWideChar(CP_ACP, 0, src, -1, dst, (int)dst_count);
	if (n <= 0) return 0;
	return 1;
}

static void log_winhttp_error_detail(const char *where, DWORD err)
{
	const char *hint = "unknown";

	switch (err) {
	case ERROR_WINHTTP_TIMEOUT:
		hint = "timeout";
		break;
	case ERROR_WINHTTP_CANNOT_CONNECT:
		hint = "cannot connect";
		break;
	case ERROR_WINHTTP_CONNECTION_ERROR:
		hint = "connection error";
		break;
	case ERROR_WINHTTP_NAME_NOT_RESOLVED:
		hint = "dns name not resolved";
		break;
	case ERROR_WINHTTP_SECURE_FAILURE:
		hint = "secure channel failure";
		break;
	case ERROR_WINHTTP_SECURE_CERT_DATE_INVALID:
		hint = "tls cert date invalid/expired";
		break;
	case ERROR_WINHTTP_SECURE_CERT_CN_INVALID:
		hint = "tls cert hostname mismatch";
		break;
	case ERROR_WINHTTP_SECURE_INVALID_CA:
		hint = "tls cert not trusted (invalid ca)";
		break;
	case ERROR_WINHTTP_SECURE_CERT_REVOKED:
		hint = "tls cert revoked";
		break;
	case ERROR_WINHTTP_SECURE_CERT_WRONG_USAGE:
		hint = "tls cert wrong usage";
		break;
	case ERROR_WINHTTP_CLIENT_AUTH_CERT_NEEDED:
		hint = "client certificate required";
		break;
	case ERROR_WINHTTP_INVALID_SERVER_RESPONSE:
		hint = "invalid server response";
		break;
	case ERROR_WINHTTP_RESEND_REQUEST:
		hint = "request must be resent";
		break;
	case ERROR_WINHTTP_LOGIN_FAILURE:
		hint = "proxy/server authentication failed";
		break;
	default:
		break;
	}

	mrlog("send_update_http: %s failed: %lu (%s)", where, err, hint);
}

struct http_target {
	int port;
	const char *host;
	unsigned long addr_s_addr;
};

static char *base64_encode(const unsigned char *src, size_t len)
{
	static const char b64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	char *out;
	size_t out_len;
	size_t i;
	size_t j;

	if (!src) return NULL;
	out_len = ((len + 2) / 3) * 4;
	out = big_malloc("base64_encode", out_len + 1);

	i = 0;
	j = 0;
	while (i < len) {
		size_t rem = len - i;
		unsigned int octet_a = src[i++];
		unsigned int octet_b = (rem > 1) ? src[i++] : 0;
		unsigned int octet_c = (rem > 2) ? src[i++] : 0;
		unsigned int triple = (octet_a << 16) | (octet_b << 8) | octet_c;

		out[j++] = b64[(triple >> 18) & 0x3F];
		out[j++] = b64[(triple >> 12) & 0x3F];
		out[j++] = (rem > 1) ? b64[(triple >> 6) & 0x3F] : '=';
		out[j++] = (rem > 2) ? b64[triple & 0x3F] : '=';
	}

	out[out_len] = '\0';
	return out;
}

static int append_auth_header(struct display *mp, char *headers, size_t headers_size)
{
	char auth_raw[512];
	char *encoded;
	int n;

	if (!mp || !headers || headers_size == 0) return 0;
	if (mp->http_username[0] == '\0') return 0;

	n = snprintf(auth_raw, sizeof auth_raw, "%s:%s", mp->http_username, mp->http_password);
	if (n < 0 || (size_t)n >= sizeof auth_raw) {
		mrlog("append_auth_header: credentials too long for target %s", mp->host);
		return 0;
	}

	encoded = base64_encode((const unsigned char *)auth_raw, (size_t)n);
	if (!encoded) return 0;
	snprcat(headers, headers_size, "Authorization: Basic %s\r\n", encoded);
	big_free("append_auth_header", encoded);
	return 1;
}

static int fill_http_target(struct display *mp, int default_port,
	struct http_target *target)
{
	if (mp) {
		target->port = mp->has_port ? ntohs(mp->in_addr.sin_port) : default_port;
		target->host = mp->host[0] ? mp->host : inet_ntoa(mp->in_addr.sin_addr);
		target->addr_s_addr = mp->in_addr.sin_addr.s_addr;
	} else {
		return 0;
	}

	if (target->port < 1 || target->port > 65535) target->port = default_port;
	mrlog("fill_http_target: using target %s:%d", target->host, target->port);
	return 1;
}

static int send_https_target(struct display *mp, const struct http_target *target,
	const char *payload, int payload_len)
{
	const char *path;
	wchar_t whost[256];
	wchar_t wpath[256];
	wchar_t wheaders[1024];
	char headers[1024];
	HINTERNET hSession;
	int timeout = http_timeout_ms;
	int attempt;

	path = http_path[0] ? http_path : MRBIG_HTTP_DEFAULT_PATH;

	if (!to_wstr(target->host, whost, sizeof whost / sizeof whost[0])
		|| !to_wstr(path, wpath, sizeof wpath / sizeof wpath[0])) {
		mrlog("send_update_http: failed string conversion for HTTPS target");
		return 0;
	}

	headers[0] = '\0';
	snprcat(headers, sizeof headers, "Content-Type: text/plain\r\n");
	append_auth_header(mp, headers, sizeof headers);
	if (!to_wstr(headers, wheaders, sizeof wheaders / sizeof wheaders[0])) {
		mrlog("send_update_http: failed header conversion for HTTPS target");
		return 0;
	}

	hSession = WinHttpOpen(L"MrBig/1.0",
		WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
		WINHTTP_NO_PROXY_NAME,
		WINHTTP_NO_PROXY_BYPASS,
		0);
	if (!hSession) {
		mrlog("send_update_http: WinHttpOpen failed: %lu", GetLastError());
		return 0;
	}

	if (timeout <= 0) timeout = MRBIG_HTTP_DEFAULT_TIMEOUT_MS;
	WinHttpSetTimeouts(hSession, timeout, timeout, timeout, timeout);

	for (attempt = 1; attempt <= http_retries; attempt++) {
		HINTERNET hConnect;
		HINTERNET hRequest;
		DWORD status = 0;
		DWORD status_len = sizeof status;
		DWORD err;

		mrlog("HTTPS attempt %d/%d: sending %d bytes to %s:%d",
			attempt, http_retries, payload_len, target->host, target->port);

		hConnect = WinHttpConnect(hSession, whost, (INTERNET_PORT)target->port, 0);
		if (!hConnect) {
			err = GetLastError();
			mrlog("send_update_http: WinHttpConnect failed (try %d/%d)",
				attempt, http_retries);
			log_winhttp_error_detail("WinHttpConnect", err);
			continue;
		}

		hRequest = WinHttpOpenRequest(hConnect,
			L"POST",
			wpath,
			NULL,
			WINHTTP_NO_REFERER,
			WINHTTP_DEFAULT_ACCEPT_TYPES,
			WINHTTP_FLAG_SECURE);
		if (!hRequest) {
			err = GetLastError();
			mrlog("send_update_http: WinHttpOpenRequest failed (try %d/%d)",
				attempt, http_retries);
			log_winhttp_error_detail("WinHttpOpenRequest", err);
			WinHttpCloseHandle(hConnect);
			continue;
		}

		if (!WinHttpSendRequest(hRequest,
			wheaders,
			-1,
			(LPVOID)payload,
			(DWORD)payload_len,
			(DWORD)payload_len,
			0)) {
			err = GetLastError();
			mrlog("send_update_http: WinHttpSendRequest failed (try %d/%d)",
				attempt, http_retries);
			log_winhttp_error_detail("WinHttpSendRequest", err);
			WinHttpCloseHandle(hRequest);
			WinHttpCloseHandle(hConnect);
			continue;
		}

		if (!WinHttpReceiveResponse(hRequest, NULL)) {
			err = GetLastError();
			mrlog("send_update_http: WinHttpReceiveResponse failed (try %d/%d)",
				attempt, http_retries);
			log_winhttp_error_detail("WinHttpReceiveResponse", err);
			WinHttpCloseHandle(hRequest);
			WinHttpCloseHandle(hConnect);
			continue;
		}

		if (!WinHttpQueryHeaders(hRequest,
			WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
			WINHTTP_HEADER_NAME_BY_INDEX,
			&status,
			&status_len,
			WINHTTP_NO_HEADER_INDEX)) {
			err = GetLastError();
			mrlog("send_update_http: WinHttpQueryHeaders failed (try %d/%d)",
				attempt, http_retries);
			log_winhttp_error_detail("WinHttpQueryHeaders", err);
			WinHttpCloseHandle(hRequest);
			WinHttpCloseHandle(hConnect);
			continue;
		}

		if (status < 200 || status >= 300) {
			mrlog("send_update_http: HTTPS non-success status %lu (try %d/%d)",
				(unsigned long)status, attempt, http_retries);
			WinHttpCloseHandle(hRequest);
			WinHttpCloseHandle(hConnect);
			continue;
		}

		WinHttpCloseHandle(hRequest);
		WinHttpCloseHandle(hConnect);
		WinHttpCloseHandle(hSession);
		return 1;
	}

	WinHttpCloseHandle(hSession);
	return 0;
}

static int send_http_target(struct display *mp, const struct http_target *target,
	const char *payload, int payload_len, char *request, int request_size)
{
	const char *path;
	SOCKET s;
	struct sockaddr_in addr;
	struct hostent *he;
	int attempt;

	path = http_path[0] ? http_path : MRBIG_HTTP_DEFAULT_PATH;

	for (attempt = 1; attempt <= http_retries; attempt++) {
		int sent = 0;
		int n;
		int request_len;
		char response[512];
		int status = 0;
		DWORD timeout = (DWORD)http_timeout_ms;

		s = INVALID_SOCKET;
		memset(&addr, 0, sizeof addr);
		mrlog("HTTP attempt %d/%d: sending %d bytes to %s:%d",
			attempt, http_retries, payload_len, target->host, target->port);

		request[0] = '\0';
		snprcat(request, request_size, "POST %s HTTP/1.1\r\n", path);
		snprcat(request, request_size, "Host: %s:%d\r\n", target->host, target->port);
		snprcat(request, request_size, "Content-Type: text/plain\r\n");
		append_auth_header(mp, request, request_size);
		snprcat(request, request_size, "Connection: close\r\n");
		snprcat(request, request_size, "Content-Length: %d\r\n\r\n", payload_len);
		snprcat(request, request_size, "%s", payload);
		request_len = (int)strlen(request);

		s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
		if (s == INVALID_SOCKET) {
			mrlog("send_update_http: socket failed: %d", WSAGetLastError());
			continue;
		}

		setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, (const char *)&timeout, sizeof timeout);
		setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char *)&timeout, sizeof timeout);

		addr.sin_family = AF_INET;
		addr.sin_port = htons(target->port);
		addr.sin_addr.s_addr = target->addr_s_addr;
		if (addr.sin_addr.s_addr == INADDR_NONE) {
			he = gethostbyname(target->host);
			if (!he || !he->h_addr_list || !he->h_addr_list[0]) {
				mrlog("send_update_http: failed to resolve host '%s'", target->host);
				closesocket(s);
				continue;
			}
			memcpy(&addr.sin_addr, he->h_addr_list[0], sizeof addr.sin_addr);
		}

		if (connect(s, (struct sockaddr *)&addr, sizeof addr) == SOCKET_ERROR) {
			mrlog("send_update_http: connect failed (try %d/%d): %d",
				attempt, http_retries, WSAGetLastError());
			closesocket(s);
			continue;
		}

		while (sent < request_len) {
			n = send(s, request + sent, request_len - sent, 0);
			if (n == SOCKET_ERROR) {
				mrlog("send_update_http: send failed (try %d/%d): %d",
					attempt, http_retries, WSAGetLastError());
				break;
			}
			sent += n;
		}

		if (sent == request_len) {
			n = recv(s, response, sizeof(response)-1, 0);
			if (n > 0) {
				response[n] = '\0';
				if (sscanf(response, "HTTP/%*d.%*d %d", &status) == 1
					&& status >= 200 && status < 300) {
					closesocket(s);
					return 1;
				}
				mrlog("send_update_http: non-success response: %.80s", response);
			} else {
				mrlog("send_update_http: no HTTP response (try %d/%d)",
					attempt, http_retries);
			}
		}

		closesocket(s);
	}

	return 0;
}

static int send_update_http_target(struct display *mp, char *p, int use_https)
{
	int payload_len;
	int request_size;
	char *request;
	int default_port;
	int ok;
	struct http_target target;

	if (!start_winsock()) return 0;

	payload_len = (int)strlen(p);
	default_port = use_https ? MRBIG_HTTPS_DEFAULT_PORT : MRBIG_HTTP_DEFAULT_PORT;
	if (!fill_http_target(mp, default_port, &target)) return 0;

	if (use_https) {
		ok = send_https_target(mp, &target, p, payload_len);
	} else {
		request_size = payload_len + 1024;
		request = big_malloc("send_update_http_target", request_size);
		ok = send_http_target(mp, &target, p, payload_len, request, request_size);
		big_free("send_update_http_target", request);
	}

	if (!ok) mrlog("send_update_http_target: failed for %s:%d after %d attempts",
		target.host, target.port, http_retries);
	return ok;
}

static int send_update_tcp_target(struct display *target, char *p)
{
	struct display *saved_head;
	struct display *saved_next;

	if (!target) return 0;
	saved_head = mrdisplay;
	saved_next = target->next;
	target->next = NULL;
	mrdisplay = target;
	send_update_tcp(p);
	mrdisplay = saved_head;
	target->next = saved_next;
	return 1;
}

void send_update_http(char *p)
{
	struct display *mp;
	int all_ok = 1;
	int have_target = 0;

	for (mp = mrdisplay; mp; mp = mp->next) {
		int ok = 0;

		have_target = 1;
		if (mp->scheme == DISPLAY_SCHEME_HTTP) {
			ok = send_update_http_target(mp, p, 0);
		} else if (mp->scheme == DISPLAY_SCHEME_HTTPS) {
			ok = send_update_http_target(mp, p, 1);
		} else {
			ok = send_update_tcp_target(mp, p);
		}

		if (!ok) all_ok = 0;
	}

	if (!have_target) {
		mrlog("send_update_http: no display target configured");
		return;
	}

	if (all_ok) mrlog("send_update_http: sent update to all displays");
	else mrlog("send_update_http: failed to send update to one or more displays");
}

void send_update_tcp(char *p)
{
	struct display *mp;
	struct sockaddr_in my_addr;
	struct hostent *he;
	struct linger l_optval;
	unsigned long nonblock;

	if (!start_winsock()) return;

	for (mp = mrdisplay; mp; mp = mp->next) {
		mp->s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
		if (mp->s == -1) {
			mrlog("send_update: socket failed: %d", WSAGetLastError());
			continue;
		}

		memset(&my_addr, 0, sizeof(my_addr));
		my_addr.sin_family = AF_INET;
		my_addr.sin_port = 0;
		my_addr.sin_addr.s_addr = inet_addr(bind_addr);
		if (bind(mp->s, (struct sockaddr *)&my_addr, sizeof my_addr) < 0) {
			mrlog("send_update: bind(%s) failed: [%d]", bind_addr, WSAGetLastError());
			closesocket(mp->s);
			mp->s = -1;
			continue;
		}

		l_optval.l_onoff = 1;
		l_optval.l_linger = 5;
		nonblock = 1;
		if (ioctlsocket(mp->s, FIONBIO, &nonblock) == SOCKET_ERROR) {
			mrlog("send_update: ioctlsocket failed: %d", WSAGetLastError());
			closesocket(mp->s);
			mp->s = -1;
			continue;
		}
		if (setsockopt(mp->s, SOL_SOCKET, SO_LINGER, (const char *)&l_optval, sizeof(l_optval)) == SOCKET_ERROR) {
			mrlog("send_update: setsockopt failed: %d", WSAGetLastError());
			closesocket(mp->s);
			mp->s = -1;
			continue;
		}

		if (debug) mrlog("Using address %s, port %d\n",
				 inet_ntoa(mp->in_addr.sin_addr),
				 ntohs(mp->in_addr.sin_port));
		if (mp->in_addr.sin_addr.s_addr == INADDR_NONE) {
			he = gethostbyname(mp->host);
			if (!he || !he->h_addr_list || !he->h_addr_list[0]) {
				mrlog("send_update: failed to resolve host '%s'", mp->host);
				closesocket(mp->s);
				mp->s = -1;
				continue;
			}
			memcpy(&mp->in_addr.sin_addr, he->h_addr_list[0], sizeof mp->in_addr.sin_addr);
		}
		if (connect(mp->s, (struct sockaddr *)&mp->in_addr, sizeof(mp->in_addr)) == SOCKET_ERROR) {
			if (WSAGetLastError() != WSAEWOULDBLOCK) {
				mrlog("send_update: connect: %d", WSAGetLastError());
				l_optval.l_onoff = 0;
				l_optval.l_linger = 0;
				setsockopt(mp->s, SOL_SOCKET, SO_LINGER, (const char *)&l_optval, sizeof(l_optval));
				closesocket(mp->s);
				mp->s = -1;
				continue;
			}
		}

		mp->pdata = p;
		mp->remaining = strlen(p);
	}

	time_t start_time = time(NULL);

	for (;;) {
		struct timeval timeo;
		fd_set wfds;
		int len;
		int tot_remaining;
		timeo.tv_sec = 1;
		timeo.tv_usec = 0;
		FD_ZERO(&wfds);
		tot_remaining = 0;
		for (mp = mrdisplay; mp; mp = mp->next) {
			if (mp->s != -1) {
				if (mp->remaining > 0) {
					FD_SET(mp->s, &wfds);
					tot_remaining += mp->remaining;
				}
			}
		}
		if (tot_remaining == 0) {
			/* all data sent to displays */
			goto cleanup;
		}
		if (time(NULL) > start_time + 10 || time(NULL) < start_time) {
			mrlog("send_update: send loop timed out");
			/* this should not take more than 10 seconds. Network problem, so bail out */
			goto cleanup;
		}
		select(255 /* ignored on winsock */, NULL, &wfds, NULL, &timeo);
		for (mp = mrdisplay; mp; mp = mp->next) {
			if (mp->s != -1) {
				if (mp->remaining > 0) {
					len = send(mp->s, mp->pdata, mp->remaining, 0);
					if (len == SOCKET_ERROR) {
						continue;
					}
					mp->pdata += len;
					mp->remaining -= len;
					if (mp->remaining == 0) {
						shutdown(mp->s, SD_BOTH);
					}
				}
			}
		}
	}

cleanup:

	/* initiate socket shutdowns */
	for (mp = mrdisplay; mp; mp = mp->next) {
		if (mp->s != -1) {
			shutdown(mp->s, SD_BOTH);
		}
	}
	/* gracefully terminate sockets, finally applying force */
	for (mp = mrdisplay; mp; mp = mp->next) {
		int i;
		if (mp->s != -1) {
			for (i = 0; i < 10; i++) {
				if (closesocket(mp->s) == WSAEWOULDBLOCK) {
					Sleep(1000); /* wait for all data to be sent */
				}
			}
			/* force the socket shut */
			l_optval.l_onoff = 0;
			l_optval.l_linger = 0;
			setsockopt(mp->s, SOL_SOCKET, SO_LINGER, (const char *)&l_optval, sizeof(l_optval));
			closesocket(mp->s);
			mp->s = -1;
		}
	}
}
