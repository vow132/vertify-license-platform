// 内部公共工具：base64url、hex、时间、UTF/宽字符转换。
#pragma once
#include <string>
#include <vector>
#include <cstdint>
#include <windows.h>
#include <winhttp.h>

namespace lumistar {

std::string b64url_encode(const uint8_t *data, size_t len);
bool b64url_decode(const std::string &in, std::vector<uint8_t> &out);
std::string to_hex(const uint8_t *data, size_t len);
std::string w2a(const std::wstring &w);
std::wstring a2w(const std::string &s);
int64_t unix_now();
std::string gen_nonce_b64(); // 16B CSPRNG -> base64url

// 最小 JSON 解析（对象/数组/字符串/数字/布尔/null，支持 \uXXXX）。
// 仅用于解析服务端响应（bootstrap/lease/redeem），拒绝畸形输入。
class Json {
public:
	static bool parse(const std::string &text, class JsonValue &out);
};

class JsonValue {
public:
	enum Type { NUL, BOOL, NUM, STR, ARR, OBJ } type = NUL;
	bool b = false;
	double num = 0;
	std::string str;
	std::vector<JsonValue> arr;
	std::vector<std::pair<std::string, JsonValue>> obj;

	const JsonValue *find(const std::string &key) const {
		for (auto &kv : obj)
			if (kv.first == key) return &kv.second;
		return nullptr;
	}
	std::string get_str(const std::string &key, const std::string &def = "") const {
		auto *v = find(key);
		return v && v->type == STR ? v->str : def;
	}
	int64_t get_i64(const std::string &key, int64_t def = 0) const {
		auto *v = find(key);
		return v && v->type == NUM ? (int64_t)v->num : def;
	}
	bool get_bool(const std::string &key, bool def = false) const {
		auto *v = find(key);
		return v && v->type == BOOL ? v->b : def;
	}
};

} // namespace lumistar
