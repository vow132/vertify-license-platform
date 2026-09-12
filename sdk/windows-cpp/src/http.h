// WinHTTP 客户端：强制 TLS（禁用明文回退），紧凑超时，40MB 安全上限。
#pragma once
#include <string>
#include <vector>
#include <cstdint>
#include <windows.h>
#include <winhttp.h>

namespace lumistar {

struct HttpResult {
	long status = 0;
	std::string body;
	std::string error; // 非 2xx 时携带错误码文本
	bool network_ok() const { return status > 0; }
	bool ok() const { return status >= 200 && status < 300; }
};

struct HttpRequest {
	std::string method = "GET";
	std::string url;                       // 仅 https://
	std::vector<std::pair<std::string, std::string>> headers;
	std::string body;
};

class HttpClient {
public:
	explicit HttpClient(const std::string &serverUrl, bool skipTlsVerify = false);
	~HttpClient();
	bool valid() const { return session_ != nullptr && connect_ != nullptr; }
	HttpResult request(const HttpRequest &req);

private:
	HINTERNET session_ = nullptr;
	HINTERNET connect_ = nullptr;
	bool skipTlsVerify_ = false;
	std::string host_;
	INTERNET_PORT port_ = 443;
};

} // namespace lumistar
