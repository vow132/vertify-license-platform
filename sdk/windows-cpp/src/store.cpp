#include "store.h"
#include "util.h"
#include <windows.h>
#include <wincrypt.h>
#include <shlwapi.h>
#include <fstream>
#include <sstream>

#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "shlwapi.lib")

namespace lumistar {

// ---- DPAPI ----

bool dpapi_protect(const std::vector<uint8_t> &in, std::vector<uint8_t> &out) {
	DATA_BLOB din{in.size(), (BYTE *)in.data()};
	DATA_BLOB dout{};
	if (!CryptProtectData(&din, L"LumistarSDK", nullptr, nullptr, nullptr, 0, &dout))
		return false;
	out.assign(dout.pbData, dout.pbData + dout.cbData);
	LocalFree(dout.pbData);
	return true;
}

bool dpapi_unprotect(const std::vector<uint8_t> &in, std::vector<uint8_t> &out) {
	DATA_BLOB din{in.size(), (BYTE *)in.data()};
	DATA_BLOB dout{};
	if (!CryptUnprotectData(&din, nullptr, nullptr, nullptr, nullptr, 0, &dout))
		return false;
	out.assign(dout.pbData, dout.pbData + dout.cbData);
	LocalFree(dout.pbData);
	return true;
}

// ---- 简单键值序列化（自绘，避免引 JSON 生成器） ----

static std::string esc(const std::string &s) {
	std::string o;
	for (char c : s) {
		if (c == '"' || c == '\\') { o += '\\'; o += c; }
		else if (c == '\n') o += "\\n";
		else o += c;
	}
	return o;
}

static std::string serialize(const SdkState &st) {
	std::ostringstream o;
	o << "{";
	o << "\"backend\":\"" << esc(st.backend) << "\",";
	o << "\"pub\":\"" << esc(st.pub_b64) << "\",";
	{
		std::string priv;
		if (!st.enc_priv.empty()) priv = b64url_encode(st.enc_priv.data(), st.enc_priv.size());
		o << "\"priv\":\"" << esc(priv) << "\",";
	}
	o << "\"lic\":\"" << esc(st.license_id) << "\",";
	o << "\"dev\":\"" << esc(st.device_id) << "\",";
	o << "\"lease\":\"" << esc(st.lease) << "\",";
	o << "\"lease_exp\":" << st.lease_exp << ",";
	o << "\"license_exp\":" << st.license_exp << ",";
	o << "\"hb\":" << st.hb_interval << ",";
	o << "\"seq\":" << st.seq << ",";
	o << "\"pins\":[";
	for (size_t i = 0; i < st.pinned_sign_keys.size(); i++) {
		if (i) o << ",";
		o << "\"" << esc(st.pinned_sign_keys[i]) << "\"";
	}
	o << "]}";
	return o.str();
}

static void parse_state(const std::string &text, SdkState &st) {
	JsonValue v;
	if (!Json::parse(text, v) || v.type != JsonValue::OBJ) return;
	st.backend = v.get_str("backend");
	st.pub_b64 = v.get_str("pub");
	std::string privB64 = v.get_str("priv");
	if (!privB64.empty()) b64url_decode(privB64, st.enc_priv);
	st.license_id = v.get_str("lic");
	st.device_id = v.get_str("dev");
	st.lease = v.get_str("lease");
	st.lease_exp = v.get_i64("lease_exp");
	st.license_exp = v.get_i64("license_exp");
	st.hb_interval = v.get_i64("hb", 60);
	st.seq = v.get_i64("seq");
	auto *pins = v.find("pins");
	if (pins && pins->type == JsonValue::ARR)
		for (auto &p : pins->arr)
			if (p.type == JsonValue::STR) st.pinned_sign_keys.push_back(p.str);
}

bool StateStore::load(const std::string &dir, SdkState &out) {
	std::string path = dir + "\\state.bin";
	std::ifstream f(path, std::ios::binary);
	if (!f) return true; // 首次运行
	std::string enc((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
	if (enc.empty()) return true;
	std::vector<uint8_t> plain;
	if (!dpapi_unprotect(std::vector<uint8_t>(enc.begin(), enc.end()), plain)) {
		// 状态损坏（换用户/换机）：重置
		DeleteFileA(path.c_str());
		return true;
	}
	parse_state(std::string(plain.begin(), plain.end()), out);
	return true;
}

bool StateStore::save(const std::string &dir, const SdkState &st) {
	// 逐级创建目录（CreateDirectoryA 只创建最后一级）
	std::string cur;
	for (size_t i = 0; i <= dir.size(); i++) {
		if (i == dir.size() || dir[i] == '\\') {
			if (!cur.empty()) CreateDirectoryA(cur.c_str(), nullptr);
			if (i == dir.size()) break;
			cur += dir[i];
		} else {
			cur += dir[i];
		}
	}
	std::string plain = serialize(st);
	std::vector<uint8_t> plainV(plain.begin(), plain.end());
	std::vector<uint8_t> enc;
	if (!dpapi_protect(plainV, enc)) return false;

	std::string path = dir + "\\state.bin";
	std::string tmp = path + ".tmp";
	{
		std::ofstream f(tmp, std::ios::binary | std::ios::trunc);
		if (!f) return false;
		f.write((const char *)enc.data(), (std::streamsize)enc.size());
	}
	MoveFileExA(tmp.c_str(), path.c_str(), MOVEFILE_REPLACE_EXISTING);
	return true;
}

} // namespace lumistar
