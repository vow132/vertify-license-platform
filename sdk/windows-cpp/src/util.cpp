// 内部工具实现。
#include "util.h"
#include <bcrypt.h>
#include <sstream>

#pragma comment(lib, "bcrypt.lib")

namespace vertify {

static const char B64C[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

std::string b64url_encode(const uint8_t *data, size_t len) {
	std::string out;
	out.reserve((len * 4 + 2) / 3);
	for (size_t i = 0; i < len; i += 3) {
		uint32_t v = data[i] << 16;
		bool b1 = i + 1 < len, b2 = i + 2 < len;
		if (b1) v |= data[i + 1] << 8;
		if (b2) v |= data[i + 2];
		out += B64C[(v >> 18) & 63];
		out += B64C[(v >> 12) & 63];
		if (b1) out += B64C[(v >> 6) & 63];
		if (b2) out += B64C[v & 63];
	}
	return out; // 无填充（RawURL，与服务端一致）
}

static int b64val(char c) {
	if (c >= 'A' && c <= 'Z') return c - 'A';
	if (c >= 'a' && c <= 'z') return c - 'a' + 26;
	if (c >= '0' && c <= '9') return c - '0' + 52;
	if (c == '-') return 62;
	if (c == '_') return 63;
	return -1;
}

bool b64url_decode(const std::string &in, std::vector<uint8_t> &out) {
	std::string s;
	s.reserve(in.size());
	for (char c : in) {
		if (c == '=') break;
		if (b64val(c) < 0 || c == '+' || c == '/') return false;
		s += c;
	}
	out.clear();
	uint32_t acc = 0;
	int bits = 0;
	for (char c : s) {
		acc = (acc << 6) | (uint32_t)b64val(c);
		bits += 6;
		if (bits >= 8) {
			bits -= 8;
			out.push_back((uint8_t)((acc >> bits) & 0xff));
		}
	}
	return true;
}

std::string to_hex(const uint8_t *data, size_t len) {
	static const char *H = "0123456789abcdef";
	std::string out;
	out.reserve(len * 2);
	for (size_t i = 0; i < len; i++) {
		out += H[data[i] >> 4];
		out += H[data[i] & 15];
	}
	return out;
}

std::string w2a(const std::wstring &w) {
	if (w.empty()) return {};
	int n = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), nullptr, 0, nullptr, nullptr);
	std::string s(n, 0);
	WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), &s[0], n, nullptr, nullptr);
	return s;
}

std::wstring a2w(const std::string &s) {
	if (s.empty()) return {};
	int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), nullptr, 0);
	std::wstring w(n, 0);
	MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), &w[0], n);
	return w;
}

int64_t unix_now() {
	return (int64_t)time(nullptr);
}

std::string gen_nonce_b64() {
	uint8_t b[16];
	if (FAILED(BCryptGenRandom(nullptr, b, sizeof(b), BCRYPT_USE_SYSTEM_PREFERRED_RNG))) {
		for (auto &x : b) x = (uint8_t)(rand() ^ (int)GetTickCount64()); // 兜底（不应到达）
	}
	return b64url_encode(b, sizeof(b));
}

// ===== JSON =====

namespace {

struct Parser {
	const char *p;
	const char *end;

	bool skip_ws() {
		while (p < end && (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n')) p++;
		return p < end;
	}
	bool parse_value(JsonValue &v, int depth) {
		if (depth > 64 || !skip_ws()) return false;
		char c = *p;
		switch (c) {
		case '{': return parse_obj(v, depth);
		case '[': return parse_arr(v, depth);
		case '"': v.type = JsonValue::STR; return parse_str(v.str);
		case 't': return lit("true", v, true);
		case 'f': return lit("false", v, false);
		case 'n': return lit("null", v, v.b);
		default: return parse_num(v);
		}
	}
	bool lit(const char *word, JsonValue &v, bool val) {
		size_t n = strlen(word);
		if ((size_t)(end - p) < n || strncmp(p, word, n) != 0) return false;
		p += n;
		if (strcmp(word, "null") == 0) v.type = JsonValue::NUL;
		else { v.type = JsonValue::BOOL; v.b = val; }
		return true;
	}
	bool parse_num(JsonValue &v) {
		char *endp = nullptr;
		double d = strtod(p, &endp);
		if (endp == p) return false;
		p = endp;
		v.type = JsonValue::NUM;
		v.num = d;
		return true;
	}
	bool parse_str(std::string &out) {
		if (*p != '"') return false;
		p++;
		out.clear();
		while (p < end) {
			char c = *p++;
			if (c == '"') return true;
			if (c == '\\') {
				if (p >= end) return false;
				char e = *p++;
				switch (e) {
				case '"': out += '"'; break;
				case '\\': out += '\\'; break;
				case '/': out += '/'; break;
				case 'b': out += '\b'; break;
				case 'f': out += '\f'; break;
				case 'n': out += '\n'; break;
				case 'r': out += '\r'; break;
				case 't': out += '\t'; break;
				case 'u': {
					if (end - p < 4) return false;
					wchar_t wc = (wchar_t)strtol(std::string(p, 4).c_str(), nullptr, 16);
					p += 4;
					// UTF-8 编码（不支持代理对组合，租约字段不使用）
					if (wc < 0x80) out += (char)wc;
					else if (wc < 0x800) {
						out += (char)(0xC0 | (wc >> 6));
						out += (char)(0x80 | (wc & 0x3F));
					} else {
						out += (char)(0xE0 | (wc >> 12));
						out += (char)(0x80 | ((wc >> 6) & 0x3F));
						out += (char)(0x80 | (wc & 0x3F));
					}
					break;
				}
				default: return false;
				}
			} else {
				out += c;
			}
		}
		return false;
	}
	bool parse_arr(JsonValue &v, int depth) {
		v.type = JsonValue::ARR;
		p++;
		if (!skip_ws()) return false;
		if (*p == ']') { p++; return true; }
		while (true) {
			JsonValue item;
			if (!parse_value(item, depth + 1)) return false;
			v.arr.push_back(std::move(item));
			if (!skip_ws()) return false;
			if (*p == ',') { p++; continue; }
			if (*p == ']') { p++; return true; }
			return false;
		}
	}
	bool parse_obj(JsonValue &v, int depth) {
		v.type = JsonValue::OBJ;
		p++;
		if (!skip_ws()) return false;
		if (*p == '}') { p++; return true; }
		while (true) {
			if (!skip_ws() || *p != '"') return false;
			std::string key;
			if (!parse_str(key)) return false;
			if (!skip_ws() || *p != ':') return false;
			p++;
			JsonValue item;
			if (!parse_value(item, depth + 1)) return false;
			v.obj.emplace_back(std::move(key), std::move(item));
			if (!skip_ws()) return false;
			if (*p == ',') { p++; continue; }
			if (*p == '}') { p++; return true; }
			return false;
		}
	}
};

} // namespace

bool Json::parse(const std::string &text, JsonValue &out) {
	Parser ps{text.data(), text.data() + text.size()};
	if (!ps.parse_value(out, 0)) return false;
	// 允许尾部空白，但不允许其它内容
	while (ps.p < ps.end) {
		if (*ps.p != ' ' && *ps.p != '\t' && *ps.p != '\r' && *ps.p != '\n') return false;
		ps.p++;
	}
	return true;
}

} // namespace vertify
