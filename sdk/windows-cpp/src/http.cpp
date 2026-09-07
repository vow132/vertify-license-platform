#include "http.h"
#include "util.h"
#include <winhttp.h>

#pragma comment(lib, "winhttp.lib")

namespace vertify {

// 解析 https://host[:port]/
static bool parse_url(const std::string &url, std::string &host, INTERNET_PORT &port) {
	const std::string https = "https://";
	if (url.rfind(https, 0) != 0) return false; // 仅 HTTPS
	std::string rest = url.substr(https.size());
	size_t slash = rest.find('/');
	if (slash != std::string::npos) rest = rest.substr(0, slash);
	size_t colon = rest.find(':');
	if (colon != std::string::npos) {
		host = rest.substr(0, colon);
		port = (INTERNET_PORT)atoi(rest.c_str() + colon + 1);
	} else {
		host = rest;
		port = 443;
	}
	return !host.empty();
}

HttpClient::HttpClient(const std::string &serverUrl, bool skipTlsVerify) {
	skipTlsVerify_ = skipTlsVerify;
	if (!parse_url(serverUrl, host_, port_)) return;
	session_ = WinHttpOpen(L"VertifySDK/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
	                       WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
	if (session_) {
		connect_ = WinHttpConnect(session_, vertify::a2w(host_).c_str(), port_, 0);
	}
}

HttpClient::~HttpClient() {
	if (connect_) WinHttpCloseHandle(connect_);
	if (session_) WinHttpCloseHandle(session_);
}

HttpResult HttpClient::request(const HttpRequest &req) {
	HttpResult res;
	if (!valid()) {
		res.error = "client not initialized";
		return res;
	}
	// 提取 path（构造时已固定 host）
	std::string path = "/";
	size_t slash = req.url.find('/', strlen("https://"));
	bool secure = (req.url.rfind("https://", 0) == 0);
	if (slash != std::string::npos) path = req.url.substr(slash);

	HINTERNET hReq = WinHttpOpenRequest(connect_, vertify::a2w(req.method).c_str(),
	                                    vertify::a2w(path).c_str(),
	                                    nullptr, WINHTTP_NO_REFERER,
	                                    WINHTTP_DEFAULT_ACCEPT_TYPES,
	                                    secure ? WINHTTP_FLAG_SECURE : 0);
	if (!hReq) {
		res.error = "open request failed";
		return res;
	}

	// 仅限开发联调：跳过证书校验（生产严禁）。必须在 SendRequest 之前设置。
	if (skipTlsVerify_) {
		DWORD secFlags = SECURITY_FLAG_IGNORE_UNKNOWN_CA |
		                 SECURITY_FLAG_IGNORE_CERT_CN_INVALID |
		                 SECURITY_FLAG_IGNORE_CERT_DATE_INVALID;
		WinHttpSetOption(hReq, WINHTTP_OPTION_SECURITY_FLAGS, &secFlags, sizeof(secFlags));
	}

	// 自定义头必须在 SendRequest 之前追加（请求头随发送一起出去）
	for (auto &kv : req.headers) {
		std::wstring h = vertify::a2w(kv.first) + L": " + vertify::a2w(kv.second) + L"\r\n";
		WinHttpAddRequestHeaders(hReq, h.c_str(), (DWORD)-1, WINHTTP_ADDREQ_FLAG_ADD);
	}

	bool sent = WinHttpSendRequest(hReq,
	                               WINHTTP_NO_ADDITIONAL_HEADERS, 0,
	                               (LPVOID)(req.body.empty() ? nullptr : req.body.data()),
	                               (DWORD)req.body.size(),
	                               (DWORD)req.body.size(), 0) != FALSE;

	if (sent && WinHttpReceiveResponse(hReq, nullptr)) {
		DWORD status = 0, size = sizeof(status);
		WinHttpQueryHeaders(hReq, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
		                    WINHTTP_HEADER_NAME_BY_INDEX, &status, &size, WINHTTP_NO_HEADER_INDEX);
		res.status = (long)status;

		for (;;) {
			DWORD avail = 0;
			if (!WinHttpQueryDataAvailable(hReq, &avail) || avail == 0) break;
			std::vector<char> buf(avail);
			DWORD read = 0;
			if (!WinHttpReadData(hReq, buf.data(), avail, &read)) break;
			res.body.append(buf.data(), read);
			if (res.body.size() > 40 * 1024 * 1024) break; // 上限
		}
	} else {
		res.status = 0;
		res.error = "network error";
	}
	WinHttpCloseHandle(hReq);
	return res;
}

} // namespace vertify
